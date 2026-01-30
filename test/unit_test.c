// this is for separately function testing
#include "main.h"
#include <linux/audit.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define ARRAY_SIZE(arr) (sizeof (arr) / sizeof (arr[0]))

static const filter filters[] = {
  BPF_STMT (BPF_LD | BPF_W | BPF_ABS, (offsetof (seccomp_data, nr))),
  BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 1, 0),
  BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1),
};

static void
load_filter (void)
{
  prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  struct sock_fprog prog
      = { .len = ARRAY_SIZE (filters), .filter = (filter *)filters };

  syscall (SYS_seccomp, SECCOMP_SET_MODE_FILTER, NULL, &prog);

  // test failed loading
  syscall (SYS_seccomp, SECCOMP_SET_MODE_FILTER, NULL, NULL);
}

int
main (void)
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
