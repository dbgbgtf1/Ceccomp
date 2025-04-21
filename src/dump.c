// clang-format off
#include "../include/dump.h"
#include <stddef.h>
#include <stdint.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdlib.h>
// clang-format on

uint64_t
SyscallHandle (syscall_info *Info, int pid, fprog *prog)
{
  uint64_t seccomp_mode = false;
  uint32_t arch = Info->arch;
  uint64_t nr = Info->entry.nr;
  uint64_t arg0 = Info->entry.args[0];

  if (nr == seccomp_syscall_resolve_name_arch (arch, "sys_seccomp"))
    seccomp_mode = arg0;
  else if (seccomp_syscall_resolve_name_arch (arch, "sys_prctl") == nr
           && seccomp_syscall_resolve_name_arch (arch, "sys_seccomp") == arg0)
    seccomp_mode = Info->entry.args[2];

  // get seccomp_mode
  // prctl (sys_seccomp, seccomp_mode, ...)
  // seccomp (seccomp_mode, ...)

  prog->len = ptrace (PTRACE_PEEKDATA, pid, Info->entry.args[2], 0);
  // also get filter, maybe we need to dump it if the seccomp succeed

  syscall_info *exitInfo = malloc (sizeof (syscall_info));
  ptrace (PTRACE_SYSCALL, pid, 0, 0);
  ptrace (PTRACE_GET_SYSCALL_INFO, pid, 0, exitInfo);

  if (exitInfo->exit.is_error)
    seccomp_mode = false;
  // seccomp set failed, nothing happened

  return seccomp_mode;
}

void
DumpFilter (syscall_info *Info, int pid, fprog *prog)
{
  size_t *tmp_filter = malloc (prog->len * sizeof (filter));
  int offset = offsetof (fprog, filter);
  size_t *filters = (size_t *)ptrace (PTRACE_PEEKDATA, pid,
                                      Info->entry.args[2] + offset, 0);

  for (int i = 0; i * WORDSIZE < prog->len * sizeof (filter); i++)
    tmp_filter[i] = ptrace (PTRACE_PEEKDATA, pid, filters[i], 0);
  // ptrace returns WORDSIZE, so use WORDSIZE as step
  // so it can work for the 32 bits

  prog->filter = (filter *)tmp_filter;
}

void
Child (char *argv[])
{
  ptrace (PTRACE_TRACEME, 0, 0, 0);
  raise (SIGSTOP);
  execv (argv[0], &argv[1]);
  // argv should start with program name
}

void
Parent (int pid)
{
  syscall_info *Info = malloc (sizeof (syscall_info));
  fprog *prog;
  uint64_t seccomp_mode;

  ptrace (PTRACE_ATTACH, pid, 0, 0);

  while (1)
    {
      ptrace (PTRACE_SYSCALL, pid, 0, 0);
      ptrace (PTRACE_GET_SYSCALL_INFO, pid, 0, Info);

      switch (Info->op)
        {
        case PTRACE_SYSCALL_INFO_ENTRY:
          seccomp_mode = SyscallHandle (Info, pid, prog);

          if (seccomp_mode == SECCOMP_SET_MODE_STRICT)
            strict ();
          else if (seccomp_mode == SECCOMP_SET_MODE_FILTER)
            {
              DumpFilter (Info, pid, prog);
              ParseFilter (Info->arch, prog);
            }

        case PTRACE_SYSCALL_INFO_EXIT:
        default:
          continue;
          // Assuming nothing important happened
        }
    }
}

void
dump (char *argv[])
{
  int pid = fork ();
  if (pid == 0)
    Child (argv);
  else
    Parent (pid);
}
