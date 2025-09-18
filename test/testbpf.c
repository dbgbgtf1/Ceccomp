// this is for separately function testing
// #include "main.h"
#include "main.h"
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define ARRAY_SIZE(arr) (sizeof (arr) / sizeof (arr[0]))

void
load_filter ()
{
  prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  /* Assume that AUDIT_ARCH_X86_64 means the normal x86-64 ABI
     (in the x32 ABI, all system calls have bit 30 set in the
     'nr' field, meaning the numbers are >= X32_SYSCALL_BIT). */

  char f[]
      = "\x20\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x02\x00\x00\x00\x06"
        "\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x01\x01\x00\x00\x06\x00"
        "\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x3b\x00\x00\x00\x06\x00\x00"
        "\x00\x00\x00\x00\x00\x15\x00\x00\x01\x38\x00\x00\x00\x06\x00\x00\x00"
        "\x00\x00\x00\x00\x15\x00\x00\x01\x39\x00\x00\x00\x06\x00\x00\x00\x00"
        "\x00\x00\x00\x15\x00\x00\x01\x3a\x00\x00\x00\x06\x00\x00\x00\x00\x00"
        "\x00\x00\x15\x00\x00\x01\x55\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00"
        "\x00\x15\x00\x00\x01\x42\x01\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00"
        "\x06\x00\x00\x00\x00\x00\xff\x7f";

  struct sock_fprog prog
      = { .len = ARRAY_SIZE (f) / sizeof (filter), .filter = (filter *)f };

  syscall (SYS_seccomp, SECCOMP_SET_MODE_FILTER, NULL, &prog);
}

int
main ()
{
  fork ();
  load_filter ();

  char buf[0x10];
  read (0, buf, 0x10);
  // scmp_filter_ctx ctx = seccomp_init (SCMP_ACT_ALLOW);
  // seccomp_rule_add (ctx, SCMP_ACT_TRAP, SCMP_SYS (execve), 0);
  // seccomp_rule_add (ctx, SCMP_ACT_LOG, SCMP_SYS (execveat), 0);
  // seccomp_load (ctx);
}
