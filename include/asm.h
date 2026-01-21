#ifndef ASM
#define ASM

#include "utils/parse_args.h"
#include <stdint.h>

extern void assemble (FILE *fp, uint32_t scmp_arch, print_mode_t print_mode);

#endif
