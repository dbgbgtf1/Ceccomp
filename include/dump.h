#ifndef DUMP
#define DUMP

#include "Main.h"
#include "parsefilter.h"
#include <stdint.h>

uint64_t SyscallHandle (syscall_info *Info, int pid, fprog *prog);

void DumpFilter (syscall_info *Info, int pid, fprog *prog);

void Child (char *argv[]);

void Parent (int pid);

void dump (char *argv[]);

#endif
