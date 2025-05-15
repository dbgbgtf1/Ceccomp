#include "probe.h"
#include "emu.h"
#include "error.h"
#include "main.h"
#include "parseargs.h"
#include "trace.h"
#include "transfer.h"
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *sysnr_tobe_test[]
    = { "open",     "read",   "write",    "execve", "execveat", "mmap",
        "mprotect", "openat", "sendfile", "ptrace", "fork" };

void
probe (int argc, char *argv[])
{
  FILE *fp = tmpfile ();
  if (fp == NULL)
    PERROR ("tmpfile");

  program_trace (argc - 1, &argv[1], fp, true);
  // oneshot mode to trace the program filter into tmpfile

  char *arch_str = parse_option_mode (argc, argv, "arch");
  uint32_t arch = STR2ARCH (arch_str);
  // get arch

  for (int i = 0; i < ARRAY_SIZE (sysnr_tobe_test); i++)
    {
      int nr = seccomp_syscall_resolve_name_arch (arch, sysnr_tobe_test[i]);
      seccomp_data data = { nr, arch, 0, { 0, 0, 0, 0, 0, 0 } };

      fseek (fp, 0, SEEK_SET);
      int stdout_backup = start_quiet ();
      char *retval_str = emu_lines (fp, &data);
      end_quiet (stdout_backup);

      if (retval_str == NULL)
        continue;

      printf ("%-10s-> %s\n", sysnr_tobe_test[i], retval_str);
    }
  // loop to emulate syscall
}
