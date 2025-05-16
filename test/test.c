// this is for separately function testing
// #include "main.h"
#include "main.h"
#include "transfer.h"
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ARRAY_SIZE(arr) (sizeof (arr) / sizeof (arr[0]))

void
load_filter (uint32_t t_arch)
{
  unsigned int upper_nr_limit = 0xffffffff;
  prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  /* Assume that AUDIT_ARCH_X86_64 means the normal x86-64 ABI
     (in the x32 ABI, all system calls have bit 30 set in the
     'nr' field, meaning the numbers are >= X32_SYSCALL_BIT). */

  char f[][8] = {
    "\x20\x00\x00\x00\x04\x00\x00\x00", "\x15\x00\x00\x05\x3e\x00\x00\xc0",
    "\x20\x00\x00\x00\x00\x00\x00\x00", "\x15\x00\x03\x00\x02\x00\x00\x00",
    "\x15\x00\x02\x00\x3b\x00\x00\x00", "\x15\x00\x01\x00\x42\x01\x00\x00",
    "\x06\x00\x00\x00\x00\x00\xff\x7f", "\x06\x00\x00\x00\x00\x00\x00\x00",
  };

  struct sock_fprog prog = { .len = ARRAY_SIZE (f), .filter = (filter *)f };

  syscall (SYS_seccomp, SECCOMP_SET_MODE_FILTER, NULL, &prog);

  char buf[0x10];
  write(1, "aaabbb\n", 0x7);
  exit(0);
}

int
main ()
{
  uint32_t arch = STR2ARCH ("x86_64");
  int pid;

  // pid_trace(68318, arch);
  load_filter (arch);
}
