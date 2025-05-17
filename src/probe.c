#include "probe.h"
#include "emu.h"
#include "error.h"
#include "main.h"
#include "trace.h"
#include <stddef.h>
#include <seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *to_test_list[]
    = { "open",     "read",   "write",    "execve", "execveat", "mmap",
        "mprotect", "openat", "sendfile", "ptrace", "fork" };

void
probe (char *argv[], uint32_t arch_token, FILE *output_fp)
{
  FILE *tmp_fp = tmpfile ();
  if (tmp_fp == NULL)
    PERROR ("tmpfile create failed");
  program_trace (argv, tmp_fp, true);

  for (int i = 0; i < ARRAY_SIZE (to_test_list); i++)
    {
      int nr = seccomp_syscall_resolve_name_arch (arch_token, to_test_list[i]);
      seccomp_data data = { nr, arch_token, 0, { 0, 0, 0, 0, 0, 0 } };

      fseek (tmp_fp, 0, SEEK_SET);
      int stdout_backup = start_quiet ();
      char *retval_str = emu_lines (tmp_fp, &data);
      end_quiet (stdout_backup);

      if (retval_str == NULL)
        continue;

      fprintf (output_fp, "%-10s-> %s\n", to_test_list[i], retval_str);
    }
}
