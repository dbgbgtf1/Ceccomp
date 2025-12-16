#ifndef DISASM
#define DISASM

#include <stdint.h>
#include <stdio.h>

extern void disasm (FILE *fp, uint32_t scmp_arch);

#endif
