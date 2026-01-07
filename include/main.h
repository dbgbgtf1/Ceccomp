#ifndef MAIN
#define MAIN

// clang-format off
#include <stdint.h>
#include <sys/ptrace.h>
#include <linux/filter.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <sys/types.h>
#include <sys/user.h>
#include "help.h"
// clang-format on

typedef struct sock_fprog fprog;
typedef struct sock_filter filter;
typedef struct seccomp_data seccomp_data;
typedef struct ptrace_syscall_info syscall_info;

typedef struct {
  char *start;
  uint16_t len;
} string_t;

#define STRAFTER(str, token)                                                  \
  (strstr (str, token) ? strstr (str, token) + strlen (token) : NULL)

#define STARTWITH(str, token) (!strncmp (str, token, strlen (token)))

#endif
