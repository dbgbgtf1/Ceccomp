#ifndef MAIN
#define MAIN

// clang-format off
#include <sys/ptrace.h>
#include <linux/filter.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <string.h>
#include <sys/user.h>
// clang-format on

#define ASM_HINT "ceccomp --asm arch text"
#define DISASM_HINT "ceccomp --disasm arch text"
#define DUMP_HINT "ceccomp --dump program [ program-args ]"
#define EMU_HINT "ceccomp --emu arch text syscall_nr [ 0-6 args ] (default as 0)"

typedef struct ptrace_syscall_info syscall_info;
typedef struct sock_fprog fprog;
typedef struct sock_filter filter;
typedef struct seccomp_data seccomp_data;
typedef struct user_regs_struct regs;

#define STRAFTER(str, token)                                                  \
  (strstr (str, token) ? strstr (str, token) + strlen (token) : NULL)

#define STARTWITH(str, token) (!strncmp (str, token, strlen (token)))

#endif
