#ifndef PROCSTATUS
#define PROCSTATUS

#include <sys/types.h>
typedef enum
{
  none,
  strict_mode,
  filter_mode
} seccomp_mode;

extern seccomp_mode get_proc_seccomp (pid_t pid);

#endif
