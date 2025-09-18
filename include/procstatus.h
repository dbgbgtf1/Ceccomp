#ifndef PROCSTATUS
#define PROCSTATUS

#include <sys/types.h>
typedef enum
{
  STATUS_NONE = 0,
  STATUS_STRICT_MODE = 1,
  STATUS_FILTER_MODE = 2,
  PROCFS_ERROR,
  STATUS_KTHREAD,
} seccomp_mode;

extern seccomp_mode get_proc_seccomp (pid_t pid);
extern seccomp_mode is_proc_kthread (pid_t pid);

#endif
