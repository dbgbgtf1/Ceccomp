// this is for separately function testing
#include "trace.h"
#include "transfer.h"
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>

#define ARRAY_SIZE(arr) (sizeof (arr) / sizeof (arr[0]))

void
load_filter (uint32_t t_arch)
{
  unsigned int upper_nr_limit = 0xffffffff;
  prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  /* Assume that AUDIT_ARCH_X86_64 means the normal x86-64 ABI
     (in the x32 ABI, all system calls have bit 30 set in the
     'nr' field, meaning the numbers are >= X32_SYSCALL_BIT). */

  struct sock_filter filter[] = {
    /* [0] Load architecture from 'seccomp_data' buffer into
           accumulator. */
    BPF_STMT (BPF_LD | BPF_W | BPF_ABS,
              (offsetof (struct seccomp_data, arch))),

    /* [1] Jump forward 5 instructions if architecture does not
           match 't_arch'. */
    BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, t_arch, 0, 5),

    /* [2] Load system call number from 'seccomp_data' buffer into
           accumulator. */
    BPF_STMT (BPF_LD | BPF_W | BPF_ABS, (offsetof (struct seccomp_data, nr))),

    /* [3] Check ABI - only needed for x86-64 in deny-list use
           cases.  Use BPF_JGT instead of checking against the bit
           mask to avoid having to reload the syscall number. */
    BPF_JUMP (BPF_JMP | BPF_JGT | BPF_K, upper_nr_limit, 3, 0),

    /* [4] Jump forward 1 instruction if system call number
           does not match 'syscall_nr'. */
    BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, 0x100, 0, 1),

    /* [5] Matching architecture and system call: don't execute
       the system call, and return 'f_errno' in 'errno'. */
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (0 & SECCOMP_RET_DATA)),

    /* [6] Destination of system call number mismatch: allow other
           system calls. */
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* [7] Destination of architecture mismatch: kill process. */
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
  };

  struct sock_fprog prog = {
    .len = ARRAY_SIZE (filter),
    .filter = filter,
  };

  if (syscall (SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog))
    {
      perror ("seccomp");
      exit (1);
    }

  char buf[0x10];
  read (0, buf, 0x10);
}

int
main ()
{
  uint32_t arch = STR2ARCH ("x86_64");
  int pid;

  pid_trace(68318, arch);
  // load_filter (arch);
}
