#ifndef RESOLVER
#define RESOLVER

#include "vector.h"
#include <stdbool.h>
#include <stdint.h>

#define LEN_VAL 0x40

extern bool has_error;

// pass the statement_t vector !!!
extern void resolver (vector_t *v, uint32_t default_arch);

#endif
