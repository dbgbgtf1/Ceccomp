// clang-format off
#include "trace.h"
#include "main.h"
#include "parsefilter.h"
#include "color.h"
#include "log/error.h"
#include <asm-generic/errno.h>
#include <errno.h>
#include <linux/ptrace.h>
#include <seccomp.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
// clang-format on

#define LOAD_SUCCESS 0x0
#define LOAD_FAIL 0x80000000

static void
strict_mode ()
{
  printf (STRICT_MODE);
}

static uint64_t
check_scmp_mode (syscall_info *Info, int pid, fprog *prog)
{
  uint64_t seccomp_mode = LOAD_FAIL;
  uint32_t arch = Info->arch;
  uint64_t nr = Info->entry.nr;
  uint64_t arg0 = Info->entry.args[0];
  uint64_t arg1 = Info->entry.args[1];

  if (nr == (uint64_t)seccomp_syscall_resolve_name_arch (arch, "seccomp"))
    seccomp_mode = arg0 | LOAD_SUCCESS;
  else if (nr == (uint64_t)seccomp_syscall_resolve_name_arch (arch, "prctl")
           && arg0 == PR_SET_SECCOMP)
    {
      if (arg1 == SECCOMP_MODE_STRICT)
        arg1 = SECCOMP_SET_MODE_STRICT;
      else if (arg1 == SECCOMP_MODE_FILTER)
        arg1 = SECCOMP_SET_MODE_FILTER;
      // prctl use different macros
      // transfer it to seccomp macros
      seccomp_mode = arg1 | LOAD_SUCCESS;
    }
  else
    return seccomp_mode;
  // get seccomp_mode
  // prctl (PR_SET_SECCOMP, seccomp_mode, &prog);
  // seccomp (seccomp_mode, 0, &prog);

  prog->len = ptrace (PTRACE_PEEKDATA, pid, Info->entry.args[2], 0);
  // also get filter len, maybe we need to dump it if the seccomp succeed

  regs exitRegs;

  ptrace (PTRACE_SINGLESTEP, pid, 0, 0);
  waitpid (pid, NULL, 0);
  ptrace (PTRACE_GETREGS, pid, 0, &exitRegs);

  if (exitRegs.rax != 0)
    seccomp_mode = LOAD_FAIL;
  // seccomp set failed, nothing happened

  return seccomp_mode;
}

static void
dump_filter (syscall_info *Info, int pid, fprog *prog)
{
  size_t *filters = (size_t *)prog->filter;
  uint32_t offset = offsetof (fprog, filter);
  uint64_t args2 = Info->entry.args[2];
  size_t *filter_adr
      = (size_t *)ptrace (PTRACE_PEEKDATA, pid, args2 + offset, 0);

  // use size_t so that it can work in both 64 and 32 bits

  for (int i = 0; i * sizeof (size_t) < prog->len * sizeof (filter); i++)
    filters[i] = ptrace (PTRACE_PEEKDATA, pid, &filter_adr[i], 0);
}

static void
filter_mode (syscall_info *Info, int pid, fprog *prog, FILE *output_fp)
{
  prog->filter = malloc (prog->len * sizeof (filter));
  dump_filter (Info, pid, prog);
  parse_filter (Info->arch, prog, output_fp);
  free (prog->filter);
}

__attribute__ ((noreturn)) static void
child (char *argv[])
{
  setpgid (0, 0);

  ptrace (PTRACE_TRACEME, 0, 0, 0);
  raise (SIGSTOP);

  int err = execv (argv[0], argv);
  if (err)
    PEXIT (EXECV_ERR ": %s, %s\n", argv[0], strerror (errno));
  exit (0);
}

static int
parent (int pid, FILE *output_fp, bool oneshot)
{
  syscall_info Info;
  fprog prog;
  uint32_t seccomp_mode;
  int status;

  waitpid (pid, &status, 0);
  ptrace (PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
  while (true)
    {
      ptrace (PTRACE_SYSCALL, pid, 0, 0);

      waitpid (pid, &status, 0);
      if (!WIFSTOPPED (status))
        return status;

      ptrace (PTRACE_GET_SYSCALL_INFO, pid, sizeof (syscall_info), &Info);

      if (Info.op != PTRACE_SYSCALL_INFO_ENTRY)
        continue;
      // Assuming nothing important happened

      seccomp_mode = check_scmp_mode (&Info, pid, &prog);

      if ((seccomp_mode & LOAD_FAIL) != 0)
        continue;
      if (seccomp_mode == (SECCOMP_SET_MODE_STRICT | LOAD_SUCCESS))
        strict_mode ();
      else if (seccomp_mode == (SECCOMP_SET_MODE_FILTER | LOAD_SUCCESS))
        filter_mode (&Info, pid, &prog, output_fp);

      if (oneshot)
        return status;
    }
}

void
program_trace (char *argv[], FILE *output_fp, bool oneshot)
{
  int pid = fork ();
  if (pid == 0)
    child (argv);
  else
    parent (pid, output_fp, oneshot);

  kill (-pid, SIGKILL);
}

void
pid_trace (int pid, uint32_t arch, FILE *output_fp)
{
  int status;
  fprog prog;
  prog.filter = malloc (sizeof (filter) * 1024);
  int prog_idx = 0;

  if (ptrace (PTRACE_SEIZE, pid, 0, 0) != 0)
    {
      switch (errno)
        {
        case EPERM:
          PEXIT ("%s", SYS_ADMIN_OR_KERNEL);
        default:
          PERROR (PTRACE_SEIZE_ERR);
        }
    }

  ptrace (PTRACE_INTERRUPT, pid, 0, 0);
  waitpid (pid, &status, 0);

  do
    {
      prog.len
          = ptrace (PTRACE_SECCOMP_GET_FILTER, pid, prog_idx, prog.filter);
      prog_idx++;

      if (prog.len != (unsigned short)-1)
        {
          parse_filter (arch, &prog, output_fp);
          continue;
        }

      switch (errno)
        {
        case ENOENT:
        case EINVAL:
          goto detach;
        case EMEDIUMTYPE:
          printf (BLUE (NOT_AN_CBPF));
          continue;
        default:
          PERROR (PTRACE_GET_FILTER_ERR);
        }
    }
  while (true);

detach:
  ptrace (PTRACE_DETACH, pid, 0, 0);
  free (prog.filter);
}
