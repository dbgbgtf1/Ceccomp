#ifndef ASM
#define ASM

#include "parseargs.h"
#include <stdint.h>
#include <stdio.h>

extern void assemble (uint32_t arch_token, FILE *read_fp, print_mode mode);

#endif
