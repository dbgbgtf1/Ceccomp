#include "procstatus.h"
#include "main.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define SECCOMP "Seccomp:"

seccomp_mode
get_proc_seccomp (pid_t pid)
{
  seccomp_mode mode;

  char proc_pid[0x100];
  snprintf (proc_pid, 0x100, "/proc/%d/status", pid);

  FILE *f = fopen (proc_pid, "r");
  if ((int64_t)f == -1)
    perror ("fopen");

  char *line = NULL;
  char *end;
  size_t size = 0;
  ssize_t nread;

  while ((nread = getline (&line, &size, f)) != -1)
    {
      if (STARTWITH (line, SECCOMP))
        {
          mode = strtoull (line + strlen(SECCOMP), &end, 10);

          if (end == line)
            return error;

          free (line);
          return mode;
        }
    }
  return error;
}
