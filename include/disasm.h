#ifndef DISASM_H
#define DISASM_H

#include "main.h"
#include <stdint.h>
#include <stdio.h>

extern void print_prog (uint32_t scmp_arch, fprog *prog, FILE *output_fp);

extern void disasm (FILE *fp, uint32_t scmp_arch);

extern filter g_filters[1024];

#endif
