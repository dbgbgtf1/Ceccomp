#ifndef DUMP
#define DUMP

#include "Main.h"
#include <stdint.h>

static void Strict ();

static uint64_t CheckSCMP (syscall_info *Info, int pid, fprog *prog);

static void DumpFilter (syscall_info *Info, int pid, fprog *prog);

static void Filter ( syscall_info * Info,  int pid, fprog * prog);

static void Child (char * argv[]);

static void Parent ( int pid);

void dump ( int argc, char * argv[]);

#endif
