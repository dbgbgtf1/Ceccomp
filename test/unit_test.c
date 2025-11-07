// this is for separately function testing
#include "main.h"
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define ARRAY_SIZE(arr) (sizeof (arr) / sizeof (arr[0]))

void
load_filter ()
{
  prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  /* Assume that AUDIT_ARCH_X86_64 means the normal x86-64 ABI
     (in the x32 ABI, all system calls have bit 30 set in the
     'nr' field, meaning the numbers are >= X32_SYSCALL_BIT). */

  char f[] = "\x20\x00\x00\x00\x00\x00\x00\x00"
             "\x15\x00\x01\x00\xff\xff\xff\xff"
             "\x06\x00\x00\x00\x00\x00\xff\x7f"
             "\x06\x00\x00\x00\x01\x00\x05\x00";

  struct sock_fprog prog
      = { .len = ARRAY_SIZE (f) / sizeof (filter), .filter = (filter *)f };

  syscall (SYS_seccomp, SECCOMP_SET_MODE_FILTER, NULL, &prog);
}

int
main ()
{
  pid_t pid = fork ();
  if (pid != 0)
    {
      wait (NULL);
      exit (0);
    }
  else
    {
      load_filter ();

      pid = fork ();
      if (pid != 0)
        exit (0);
      signal (SIGINT, SIG_IGN);
      sleep (100);
    }
}
