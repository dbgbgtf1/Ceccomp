#ifndef MAIN
#define MAIN

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/user.h>

typedef struct ptrace_syscall_info syscall_info;
typedef struct sock_fprog fprog;
typedef struct sock_filter filter;
typedef struct seccomp_data seccomp_data;
typedef struct user_regs_struct regs;

#endif
