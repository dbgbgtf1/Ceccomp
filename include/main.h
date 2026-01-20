#ifndef MAIN
#define MAIN

// clang-format off
#include <stdbool.h>
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

typedef struct
{
  const char *start;
  uint32_t len;
} string_t;

extern bool has_error;

#define STARTWITH(str, token) (!strncmp (str, token, strlen (token)))

#define LIKELY(x) __builtin_expect (!!(x), 1)
#define UNLIKELY(x) __builtin_expect (!!(x), 0)

#define ARRAY_SIZE(arr) (sizeof (arr) / sizeof (arr[0]))
#define LITERAL_STRLEN(str) (ARRAY_SIZE (str) - 1)
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
