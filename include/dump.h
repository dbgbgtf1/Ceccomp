#ifndef DUMP
#define DUMP

#include "main.h"
#include <stdint.h>

static void strict_mode ();

static uint64_t check_scmp_mode (syscall_info *Info, int pid, fprog *prog);

static void dump_filter (syscall_info *Info, int pid, fprog *prog);

static void filter_mode (syscall_info *Info, int pid, fprog *prog);

static void child (char *argv[]);

static void parent (int pid);

extern void dump (int argc, char *argv[]);

#endif
