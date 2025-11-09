#include "probe.h"
#include "emu.h"
#include "log/logger.h"
#include "main.h"
#include "trace.h"
#include <fcntl.h>
#include <seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *to_test_list[]
    = { "open", "openat",   "read",     "write",  "execve", "execveat",
        "mmap", "mprotect", "sendfile", "ptrace", "fork" };

void
probe (char *argv[], FILE *output_fp)
{
  FILE *tmp_fp = tmpfile ();
  if (tmp_fp == NULL)
    error ("open: %s", strerror (errno));
  uint32_t arch_token = program_trace (argv, tmp_fp, true);

  for (size_t i = 0; i < ARRAY_SIZE (to_test_list); i++)
    {
      int nr = seccomp_syscall_resolve_name_arch (arch_token, to_test_list[i]);
      seccomp_data data = { nr, arch_token, 0, { 0, 0, 0, 0, 0, 0 } };

      fseek (tmp_fp, 0, SEEK_SET);
      char *retval_str = emu_lines (true, tmp_fp, &data);

      if (retval_str == NULL)
        continue;

      fprintf (output_fp, "%-10s-> %s\n", to_test_list[i], retval_str);
    }

  fclose (tmp_fp);
}
