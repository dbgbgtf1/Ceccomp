#ifndef MAIN
#define MAIN

// clang-format off
#include <sys/ptrace.h>
#include <linux/filter.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <sys/types.h>
#include <sys/user.h>
#include "help.h"
// clang-format on

#define CECCOMP_VERSION "ceccomp 2.8"

typedef struct sock_fprog fprog;
typedef struct sock_filter filter;
typedef struct seccomp_data seccomp_data;

#define STRAFTER(str, token)                                                  \
  (strstr (str, token) ? strstr (str, token) + strlen (token) : NULL)

#define STARTWITH(str, token) (!strncmp (str, token, strlen (token)))

#endif
