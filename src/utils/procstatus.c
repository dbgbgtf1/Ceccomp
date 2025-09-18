#include "procstatus.h"
#include "main.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define SECCOMP "Seccomp:"
// the sizeof simply including appending \t or space
#define SECCOMP_OFFSET (sizeof (SECCOMP))
#define KTHREAD "Kthread:"
#define KTHREAD_OFFSET (sizeof (KTHREAD))

// -1 for errors, else return fetched number
static long
access_proc_with_key (pid_t pid, const char *comparator, size_t strsize)
{
  long value = -1;
  char buf[0x40];
  char *end;
  snprintf (buf, 0x40, "/proc/%d/status", pid);

  FILE *f = fopen (buf, "r");
  if (f == NULL)
    return -1;

  while (fgets (buf, 0x40, f))
    if (STARTWITH (buf, comparator))
      {
        value = strtoull (buf + strsize, &end, 10);
        if (end == buf + strsize)
          value = -1;
        break;
      }

  fclose (f);
  return value;
}

seccomp_mode
get_proc_seccomp (pid_t pid)
{
  long ret = access_proc_with_key (pid, SECCOMP, SECCOMP_OFFSET);
  if (ret == -1)
    return PROCFS_ERROR;
  return (seccomp_mode)ret;
}

seccomp_mode
is_proc_kthread (pid_t pid)
{
  long ret = access_proc_with_key (pid, KTHREAD, KTHREAD_OFFSET);
  if (ret == -1)
    return PROCFS_ERROR;
  if (ret == 1)
    return STATUS_KTHREAD;
  // ret == 0
  return STATUS_NONE;
}
