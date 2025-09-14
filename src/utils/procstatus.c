#include "procstatus.h"
#include "log/error.h"
#include "log/logger.h"
#include "parseargs.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define SECCOMP "Seccomp:"

seccomp_mode
get_proc_seccomp (pid_t pid)
{
  char proc_pid[0x100];
  snprintf (proc_pid, 0x100, "/proc/%d/status", pid);

  FILE *f = fopen (proc_pid, "r");
  if ((int64_t)f == -1)
    perror ("fopen");

  char *line = NULL;
  size_t size = 0;
  ssize_t nread;

  while ((nread = getline (&line, &size, f)) != -1)
    {
      if (strstr (line, SECCOMP))
        {
          line += strlen (SECCOMP);
          return strtoull_check (line, 10, FAIL_READ_PROC_STATUS);
        }
    }

  error ("%s", FAIL_READ_PROC_STATUS);
}
