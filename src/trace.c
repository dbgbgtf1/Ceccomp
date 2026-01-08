#include "trace.h"
#include "color.h"
#include "disasm.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include "proc_status.h"
#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <assert.h>
#include <complex.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOAD_FAIL 2

static void
mode_strict (void)
{
  printf (RED ("%s\n"), _ ("STRICT MODE DETECTED!"));
  printf (RED ("%s\n"), _ ("Only read, write, _exit, sigreturn available!"));
}

static uint64_t seccomp_nr;
static uint64_t prctl_nr;
static uint32_t saved_arch = -1;

static uint64_t
check_scmp_mode (syscall_info info, int pid, fprog *prog)
{
  uint64_t seccomp_mode = LOAD_FAIL;
  uint64_t nr = info.entry.nr;
  uint64_t arg0 = info.entry.args[0];
  uint64_t arg1 = info.entry.args[1];

  if (nr == seccomp_nr
      && (arg0 == SECCOMP_SET_MODE_FILTER || arg0 == SECCOMP_MODE_STRICT))
    seccomp_mode = arg0;
  else if (nr == prctl_nr && arg0 == PR_SET_SECCOMP)
    {
      if (arg1 == SECCOMP_MODE_STRICT)
        arg1 = SECCOMP_SET_MODE_STRICT;
      else if (arg1 == SECCOMP_MODE_FILTER)
        arg1 = SECCOMP_SET_MODE_FILTER;
      // prctl use different macros
      // transfer it to seccomp macros
      seccomp_mode = arg1;
    }
  else
    return seccomp_mode;
  // get seccomp_mode
  // prctl (PR_SET_SECCOMP, seccomp_mode, &prog);
  // seccomp (seccomp_mode, 0, &prog);

  prog->len = ptrace (PTRACE_PEEKDATA, pid, info.entry.args[2], 0);
  // also get filter len, maybe we need to dump it if the seccomp succeed

  ptrace (PTRACE_SYSCALL, pid, 0, 0);
  waitpid (pid, NULL, 0);
  ptrace (PTRACE_GET_SYSCALL_INFO, pid, sizeof (syscall_info), &info);

  assert (info.op == PTRACE_SYSCALL_INFO_EXIT);

  if (info.exit.is_error)
    seccomp_mode = LOAD_FAIL;
  // seccomp set failed, nothing happened

  return seccomp_mode;
}

static size_t
peek_data_check (pid_t pid, size_t *addr)
{
  errno = 0;
  size_t result = ptrace (PTRACE_PEEKDATA, pid, addr, 0);
  if (result == (size_t)-1 && errno != 0)
    error (M_PEEKDATA_FAILED_ADR, (void *)addr);
  return result;
}

static void
dump_filter (syscall_info *info, int pid, fprog *prog)
{
  size_t *filters = (size_t *)prog->filter;
  // args2 is the prog addrs
  uint64_t args2 = info->entry.args[2];

  uint32_t offset = offsetof (fprog, filter);
  bool is_local_64 = (sizeof (void *) == 8);
  bool is_target_64 = info->arch & __AUDIT_ARCH_64BIT;

  if (is_local_64 && !is_target_64)
    offset /= 2;
  else if (!is_local_64 && is_target_64)
    error ("%s", M_CANNOT_WORK_FROM_32_TO_64);

  size_t filter_adr
      = peek_data_check (pid, (size_t *)((size_t)args2 + offset));
  if (is_local_64 && !is_target_64)
    filter_adr &= 0xffffffff;

  // use size_t so that it can work in both 64 and 32 bits
  for (int i = 0; i * sizeof (size_t) < prog->len * sizeof (filter); i++)
    filters[i] = peek_data_check (pid, &((size_t *)filter_adr)[i]);
}

static void
mode_filter (syscall_info *info, int pid, fprog *prog, FILE *output_fp)
{
  prog->filter = malloc (prog->len * sizeof (filter));
  dump_filter (info, pid, prog);
  print_prog (info->arch, prog, output_fp);
  free (prog->filter);
  prog->filter = 0;
}

__attribute__ ((noreturn)) static void
child (char *argv[])
{
  ptrace (PTRACE_TRACEME, 0, 0, 0);
  raise (SIGSTOP);

  int err = execv (argv[0], argv);
  if (err)
    error ("%s: %s, %s\n", M_EXECV_ERR, argv[0], strerror (errno));
  exit (0);
}

static void
handle_fork (pid_t pid, int status)
{
  int event = (status >> 16) & 0xffff;
  if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK
      || event == PTRACE_EVENT_CLONE)
    {
      uint64_t new_pid;
      ptrace (PTRACE_GETEVENTMSG, pid, NULL, &new_pid);
      info (M_PROCESS_FORK, pid, (pid_t)new_pid);
    }
}

static bool
handle_syscall (pid_t pid, FILE *output_fp, bool oneshot)
{
  syscall_info info;
  fprog prog;
  uint32_t seccomp_mode;

  ptrace (PTRACE_GET_SYSCALL_INFO, pid, sizeof (info), &info);
  if (info.op != PTRACE_SYSCALL_INFO_ENTRY)
    return false;

  if (info.arch != saved_arch)
    {
      saved_arch = info.arch;
      seccomp_nr = seccomp_syscall_resolve_name_arch (saved_arch, "seccomp");
      prctl_nr = seccomp_syscall_resolve_name_arch (saved_arch, "prctl");
      // every arch has prctl, so if prctl has no nr, seccomp has no nr, either
      if (prctl_nr == (uint64_t)__NR_SCMP_ERROR)
        error (M_TRACEE_ARCH_NOT_SUPPORTED, saved_arch);
    }

  seccomp_mode = check_scmp_mode (info, pid, &prog);

  if (seccomp_mode != LOAD_FAIL)
    info (M_PARSE_PID_BPF, pid);
  if (seccomp_mode == SECCOMP_SET_MODE_STRICT)
    mode_strict ();
  else if (seccomp_mode == SECCOMP_SET_MODE_FILTER)
    mode_filter (&info, pid, &prog, output_fp);

  if (!oneshot || seccomp_mode == LOAD_FAIL)
    return false;

  return true;
}

static uint32_t
parent (pid_t child_pid, FILE *output_fp, bool oneshot)
{
  int status;

  waitpid (child_pid, &status, 0);
  // child is stopped after PTRACE_TRACEME

  // clang-format off
  ptrace (PTRACE_SETOPTIONS, child_pid, 0,
          PTRACE_O_TRACESYSGOOD
          | PTRACE_O_TRACEFORK
          | PTRACE_O_TRACEVFORK
          | PTRACE_O_TRACECLONE
          | PTRACE_O_EXITKILL);
  // clang-format on

  ptrace (PTRACE_SYSCALL, child_pid, 0, 0);
  while (1)
    {
      pid_t pid = waitpid (-1, &status, __WALL);
      if (pid == -1)
        {
          if (errno == ECHILD)
            exit (0);
          continue;
        }

      if (WIFEXITED (status) || WIFSIGNALED (status))
        {
          info (M_PROCESS_EXIT, pid);
          continue;
        }

      if (WIFCONTINUED (status))
        continue;

      int sig = WSTOPSIG (status);
      if (sig == (SIGTRAP | 0x80))
        {
          if (handle_syscall (pid, output_fp, oneshot))
            return saved_arch;
          ptrace (PTRACE_SYSCALL, pid, 0, 0);
        }
      else if (sig == SIGTRAP)
        {
          handle_fork (pid, status);
          ptrace (PTRACE_SYSCALL, pid, 0, 0);
        }
      else
        ptrace (PTRACE_SYSCALL, pid, 0, sig);
    }
}

static void
exit_on_sig (int signo)
{
  // flush files when recved normal signals
  exit (signo);
}

uint32_t
program_trace (char *argv[], FILE *output_fp, bool oneshot)
{
  signal (SIGINT, exit_on_sig);
  signal (SIGTERM, exit_on_sig);
  int pid = fork ();
  if (pid == 0)
    child (argv);
  else
    return parent (pid, output_fp, oneshot);
}

static void
einval_get_filter (pid_t pid)
{
  seccomp_mode mode = get_proc_seccomp (pid);
  if ((int)mode == PROCFS_ERROR)
    error ("%s %s, %s", M_PROCFS_NOT_ACCESSIBLE, ACTION_GET_FILTER,
           M_GET_FILTER_UNSUPPORTED_OR_NO_FILTER);
  if (mode == STATUS_STRICT_MODE)
    {
      mode_strict ();
      exit (0);
    }
  else if (mode == STATUS_FILTER_MODE)
    error ("%s", M_GET_FILTER_UNSUPPORTED);
  // if mode == STATUS_NONE, return to print "no filters found"
}

__attribute__ ((noreturn)) static void
eacces_get_filter (pid_t pid)
{
  seccomp_mode mode = get_proc_seccomp (pid);
  if ((int)mode == PROCFS_ERROR)
    error ("%s %s, %s", M_PROCFS_NOT_ACCESSIBLE, ACTION_GET_FILTER,
           M_CAP_SYS_ADMIN_OR_IN_SECCOMP);
  if (mode == STATUS_NONE)
    error ("%s", M_REQUIRE_CAP_SYS_ADMIN);
  else
    error ("%s", M_CECCOMP_IN_SECCOMP);
}

// return true means continue
// else break
static bool
error_get_filter (pid_t pid, int err)
{
  switch (err)
    {
    case ENOENT:
      return false;
    case EINVAL:
      einval_get_filter (pid);
      return false;
    case EACCES:
      eacces_get_filter (getpid ());
    case EMEDIUMTYPE:
      warn ("%s", M_NOT_AN_CBPF);
      return true;
    default:
      error ("trace: %s", strerror (err));
    }
}

__attribute__ ((noreturn)) static void
eperm_seize (pid_t pid)
{
  // seizing a thread in the same thread group may cause EPERM
  // but that will probably not happen
  kthread_mode mode = is_proc_kthread (pid);
  if ((int)mode == PROCFS_ERROR)
    error ("%s %s, %s", M_PROCFS_NOT_ACCESSIBLE, ACTION_PTRACE_SEIZE,
           M_CAP_SYS_PTRACE_OR_KTHREAD);
  if (mode == STATUS_KTHREAD)
    error ("%s", M_SEIZING_KERNEL_THREAD);

  pid_t tracer = get_tracer_pid (pid);
  assert (tracer != PROCFS_ERROR);

  if (tracer)
    error (M_TARGET_TRACED_BY, tracer);
  else
    error ("%s", M_REQUIRE_CAP_SYS_PTRACE);
  // seize needs CAP_SYS_PTRACE
  // get_filter needs CAP_SYS_ADMIN
}

static void
error_seize (pid_t pid, int err)
{
  switch (err)
    {
    case EPERM:
      eperm_seize (pid);
    default:
      error ("trace: %s", strerror (err));
    }
}

void
pid_trace (int pid)
{
  fprog prog;
  prog.filter = malloc (sizeof (filter) * 1024);
  int prog_idx = 0;

  if (ptrace (PTRACE_SEIZE, pid, 0, 0) != 0)
    error_seize (pid, errno);

  ptrace (PTRACE_INTERRUPT, pid, 0, 0);
  waitpid (pid, NULL, 0);

  syscall_info info;
  ptrace (PTRACE_GET_SYSCALL_INFO, pid, sizeof (info), &info);
  uint32_t scmp_arch = info.arch;

  while (true)
    {
      prog.len
          = ptrace (PTRACE_SECCOMP_GET_FILTER, pid, prog_idx, prog.filter);

      if (prog.len != (unsigned short)-1)
        {
          print_prog (scmp_arch, &prog, stdout);
          prog_idx++;
          continue;
        }

      if (!error_get_filter (pid, errno))
        break;
    }

  if (prog_idx == 0)
    printf (M_NO_FILTER_FOUND, pid);
  ptrace (PTRACE_DETACH, pid, 0, 0);
  free (prog.filter);
}
