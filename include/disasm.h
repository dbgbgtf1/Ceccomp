#ifndef DISASM_H
#define DISASM_H

#include "main.h"
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

extern void print_prog (uint32_t scmp_arch, fprog *prog, FILE *output_fp, bool trustful);

extern void disasm (FILE *fp, uint32_t scmp_arch);

extern filter *g_filters;

// return true if success or initialized
extern bool init_global_filters(void);

#endif
