#ifndef RESOLVER_H
#define RESOLVER_H

#include "utils/vector.h"
#include <stdbool.h>
#include <stdint.h>

#define _SCMP_ACT_TRAP(x) (SCMP_ACT_TRAP | ((x) & 0x0000ffffU))

// see vector.h for vector details
// return false if ok, return true if error occurs
extern bool resolver (vector_t *code_ptr_v);

#endif
