#ifndef PARSEOBJ
#define PARSEOBJ

#include "emu.h"
#include "main.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct
{
  uint8_t reg_len;
  uint32_t *reg_ptr;
} reg_set;

#define GETJT(jmpset) ((jmpset & 0xffff0000) >> 16)
#define GETJF(jmpset) (jmpset & 0x0000ffff)
#define JMPSET(jt, jf) ((jt << 16) | jf)

#define GETSYMLEN(symset) ((symset & 0xf0) >> 4)

typedef enum
{
  CMP_GT = 0x10,
  CMP_LT = 0x11,
  CMP_AD = 0x12,

  CMP_EQ = 0x20,
  CMP_NE = 0x21,
  CMP_LE = 0x22,
  CMP_GE = 0x23,

  ALU_AN = 0x20,
  ALU_AD = 0x21,
  ALU_SU = 0x22,
  ALU_ML = 0x23,
  ALU_DV = 0x24,
  ALU_OR = 0x25,
  ALU_XO = 0x26,
  ALU_NG = 0x27,

  ALU_LS = 0x30,
  ALU_RS = 0x31
} Sym;

extern uint32_t right_val_ifline (char *val_str, reg_mem *reg, uint32_t arch);

extern uint32_t right_val_assignline (FILE *s_output_fp, char *rval_str, reg_mem *reg_ptr);

extern void left_val_assignline (char *lval_str, reg_set *reg_len_ptr,
                                 reg_mem *reg_ptr);

extern uint8_t parse_cmp_sym (char *sym_str);

extern uint8_t parse_alu_sym (char *sym_str);

extern uint32_t parse_goto (char *goto_str);

extern bool maybe_reverse (char *clean_line);

#endif
