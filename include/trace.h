#ifndef TRACE
#define TRACE

// clang-format off
#include <stdbool.h>
#include <stdio.h>
#define STRICT_MODE                     \
  "---------------------------------\n" \
  RED ("Strict Mode Detected?!\n")      \
  RED ("Only read, write, _exit!\n")    \
  "---------------------------------\n"
// clang-format on

extern void program_trace (int argc, char *argv[], FILE *fp, bool oneshot);

extern void trace (int argc, char *argv[]);

#endif
