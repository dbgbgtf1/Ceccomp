#ifndef DISASM
#define DISASM

#include <stdint.h>
#include <stdio.h>

extern void disasm (uint32_t arch_token, FILE *read_fp);

#endif
