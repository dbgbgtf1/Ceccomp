#ifndef ASM
#define ASM

#include "main.h"
#include "preasm.h"
#include <stdbool.h>
#include <stdint.h>

static filter MISC_TXA ();

static filter MISC_TAX ();

static uint16_t jmp_mode (uint8_t sym_enum, bool *reverse, char *origin_line);

static void jmp_src (char *rval, filter *f_ptr, uint32_t arch,
                     char *origin_line);

static filter JMP (line_set *Line, uint32_t idx, uint32_t arch);

static bool LD_LDX_ABS (char *rvar, filter *f_ptr);

static bool LD_LDX_MEM (char *rvar, filter *f_ptr, char *origin_line);

static bool LD_LDX_IMM (char *rvar, filter *f_ptr, uint32_t arch,
                        char *origin_line);

static filter LD_LDX (line_set *Line, uint32_t arch);

static filter RET (line_set *Line);

static filter ST_STX (line_set *Line);

static void asm_lines (FILE *fp, unsigned arch);

extern void assemble (int argc, char *argv[]);

#endif
