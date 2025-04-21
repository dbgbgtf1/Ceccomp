#ifndef DUMP
#define DUMP

#include "Main.h"
#include <stdint.h>

static void Strict();

// clang-format on
static const uint64_t CheckSCMP (const syscall_info *const Info, const int pid, fprog * const prog);

static void DumpFilter (const syscall_info *const Info, const int pid, fprog *const prog);
// clang-format off

static void Filter (const syscall_info *const Info, const int pid, fprog *const prog);

static void Child (char *const argv[]);

static void Parent (const int pid);

extern void dump (const int argc, char *const argv[]);

#endif
