// clang-format off
#include "dump.h"
#include "Main.h"
#include "parsefilter.h"
#include "error.h"
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <linux/ptrace.h>
#include <seccomp.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
// clang-format on

#define LOADED 0x8

void
Strict ()
{
  printf ("Strict Mode Detected?!\n");
  printf ("Only read, write, _exit!\n");
}

const uint64_t
CheckSCMP (const syscall_info *const Info, const int pid, fprog * const prog)
{
  uint64_t seccomp_mode = false;
  uint32_t arch = Info->arch;
  uint64_t nr = Info->entry.nr;
  uint64_t arg0 = Info->entry.args[0];
  uint64_t arg1 = Info->entry.args[1];

  if (nr == seccomp_syscall_resolve_name_arch (arch, "seccomp"))
    seccomp_mode = arg0 | LOADED;
  else if (nr == seccomp_syscall_resolve_name_arch (arch, "prctl")
           && arg0 == PR_SET_SECCOMP)
    seccomp_mode = arg1 | LOADED;
  else
    return seccomp_mode;

  // get seccomp_mode
  // prctl (PR_SET_SECCOMP, seccomp_mode, &prog);
  // seccomp (seccomp_mode, 0, &prog);

  prog->len = ptrace (PTRACE_PEEKDATA, pid, Info->entry.args[2], 0);
  // also get filter len, maybe we need to dump it if the seccomp succeed

  regs *exitRegs = malloc (sizeof (regs));
  ptrace (PTRACE_SINGLESTEP, pid, 0, 0);
  waitpid (pid, NULL, 0);
  ptrace (PTRACE_GETREGS, pid, 0, exitRegs);
  if (exitRegs->rax != 0)
    seccomp_mode = false;
  // seccomp set failed, nothing happened

  return seccomp_mode;
}

void
DumpFilter (const syscall_info *const Info, const int pid, fprog *const prog)
{
  size_t *sFilter = (size_t *)prog->filter;
  uint32_t offset = offsetof (fprog, filter);
  uint64_t args2 = Info->entry.args[2];
  size_t *cFilter = (size_t *)ptrace (PTRACE_PEEKDATA, pid, args2 + offset, 0);

  // use size_t so that it can work in both 64 and 32 bits

  for (int i = 0; i * sizeof (size_t) < prog->len * sizeof (filter); i++)
    sFilter[i] = ptrace (PTRACE_PEEKDATA, pid, &cFilter[i], 0);
}

void
Filter (const syscall_info *const Info, const int pid, fprog *const prog)
{
  prog->filter = malloc (prog->len * sizeof (filter));
  DumpFilter (Info, pid, prog);
  ParseFilter (Info->arch, prog);
  free (prog->filter);
}

void
Child (char *const argv[])
{
  ptrace (PTRACE_TRACEME, 0, 0, 0);
  raise (SIGSTOP);

  int err = execv (argv[0], argv);
  if (err)
    PEXIT ("execv failed %s", argv[0]);
  // argv should start with program name
}

void
Parent (const int pid)
{
  syscall_info *Info = malloc (sizeof (syscall_info));
  fprog *prog = malloc (sizeof (fprog));
  uint32_t seccomp_mode;
  int status;

  waitpid (pid, &status, 0);
  ptrace (PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
  while (true)
    {
      ptrace (PTRACE_SYSCALL, pid, 0, 0);

      waitpid (pid, &status, 0);
      if (!WIFSTOPPED (status))
        PEXIT ("child process status: %d", status);

      ptrace (PTRACE_GET_SYSCALL_INFO, pid, sizeof (syscall_info), Info);

      if (Info->op != PTRACE_SYSCALL_INFO_ENTRY)
        continue;
      // Assuming nothing important happened

      seccomp_mode = CheckSCMP (Info, pid, prog);

      if (seccomp_mode == (SECCOMP_SET_MODE_STRICT | LOADED))
        Strict ();
      else if (seccomp_mode == (SECCOMP_SET_MODE_FILTER | LOADED))
        Filter (Info, pid, prog);
    }

  free (Info);
  free (prog);
}

void
dump (const int argc, char *const argv[])
{
  if (argc <= 2)
    PEXIT ("%s", "usage: Ceccomp dump program prgram-args");

  int pid = fork ();
  if (pid == 0)
    Child (argv);
  else
    Parent (pid);
}
