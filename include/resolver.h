#ifndef RESOLVER
#define RESOLVER

#include "vector.h"
#include <stdbool.h>
#include <stdint.h>

#define LEN_VAL 0x40
#define _SCMP_ACT_TRAP(x) (SCMP_ACT_TRAP | ((x) & 0x0000ffffU))

extern bool has_error;

// pass the statement_t vector !!!
// return false if ok, return true if error occurs
extern bool resolver (vector_t *v);

#endif
