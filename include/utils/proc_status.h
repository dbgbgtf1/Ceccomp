#ifndef PROCSTATUS_H
#define PROCSTATUS_H

#include <sys/types.h>
#define PROCFS_ERROR -1

typedef enum
{
  STATUS_NONE = 0,
  STATUS_STRICT_MODE = 1,
  STATUS_FILTER_MODE = 2,
} seccomp_mode;

typedef enum
{
  STATUS_NOT_KTHREAD = 0,
  STATUS_KTHREAD = 1,
} kthread_mode;

extern seccomp_mode get_proc_seccomp (pid_t pid);
extern kthread_mode is_proc_kthread (pid_t pid);
extern pid_t get_tracer_pid (pid_t pid);

#endif
