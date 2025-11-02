#include <linux/filter.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define ARRAY_SIZE(arr) (sizeof (arr) / sizeof (arr[0]))

int
main ()
{
  prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

  pid_t pid = fork ();
  if (pid == 0)
    {
      char f[] = "\x20\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x02\x00\x00"
                 "\x00\x06"
                 "\x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x01\x01\x00\x00"
                 "\x06\x00"
                 "\x00\x00\x00\x00\x00\x00\x15\x00\x00\x01\x3b\x00\x00\x00\x06"
                 "\x00\x00"
                 "\x00\x00\x00\x00\x00\x15\x00\x00\x01\x38\x00\x00\x00\x06\x00"
                 "\x00\x00"
                 "\x00\x00\x00\x00\x15\x00\x00\x01\x39\x00\x00\x00\x06\x00\x00"
                 "\x00\x00"
                 "\x00\x00\x00\x15\x00\x00\x01\x3a\x00\x00\x00\x06\x00\x00\x00"
                 "\x00\x00"
                 "\x00\x00\x15\x00\x00\x01\x55\x00\x00\x00\x06\x00\x00\x00\x00"
                 "\x00\x00"
                 "\x00\x15\x00\x00\x01\x42\x01\x00\x00\x06\x00\x00\x00\x00\x00"
                 "\x00\x00"
                 "\x06\x00\x00\x00\x00\x00\xff\x7f";
      struct sock_fprog prog
          = { .len = ARRAY_SIZE (f) / sizeof (struct sock_filter),
              .filter = (struct sock_filter *)f };

      syscall (SYS_seccomp, SECCOMP_SET_MODE_FILTER, NULL, &prog);
    }
  else
    {
      scmp_filter_ctx ctx = seccomp_init (SCMP_ACT_ALLOW);
      seccomp_rule_add (ctx, SCMP_ACT_TRAP, SCMP_SYS (execve), 0);
      seccomp_rule_add (ctx, SCMP_ACT_LOG, SCMP_SYS (execveat), 0);
      seccomp_load (ctx);
    }
}
