#ifndef TRACE
#define TRACE

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

typedef struct user_regs_struct regs;
typedef struct ptrace_syscall_info syscall_info;

// return arch_token
extern uint32_t program_trace (char *argv[], FILE *output_fp, bool oneshot);

extern void pid_trace (int pid);

#endif
