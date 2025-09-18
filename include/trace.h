#ifndef TRACE
#define TRACE

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

typedef struct user_regs_struct regs;
typedef struct ptrace_syscall_info syscall_info;

extern void program_trace (char *argv[], FILE *output_fp, bool oneshot);

extern void pid_trace (int pid, uint32_t arch);

#endif
