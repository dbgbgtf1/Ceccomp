#ifndef TRACE
#define TRACE

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
// clang-format off
#define STRICT_MODE                     \
  "---------------------------------\n" \
  RED ("Strict Mode Detected?!\n")      \
  RED ("Only read, write, _exit!\n")    \
  "---------------------------------\n"
// clang-format on

typedef struct user_regs_struct regs;
typedef struct ptrace_syscall_info syscall_info;

extern void program_trace (char *argv[], FILE *output_fp, bool oneshot);

extern void pid_trace (int pid, uint32_t arch);

#endif
