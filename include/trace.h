#ifndef TRACE
#define TRACE

#include "main.h"
#include <stdint.h>

extern void pid_trace (int pid, uint32_t arch);

extern void trace (int argc, char *argv[]);

#endif
