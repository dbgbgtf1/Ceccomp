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
  SYM_GT = 0x10,
  SYM_LT = 0x11,
  SYM_AD = 0x12,

  SYM_EQ = 0x23,
  SYM_NE = 0x24,
  SYM_LE = 0x25,
  SYM_GE = 0x26,
} Sym;

extern uint32_t right_val_ifline (char *val_str, reg_mem *reg, uint32_t arch,
                                  char *origin_line);

extern uint32_t right_var_assignline (char *rvar_str, seccomp_data *data,
                                      reg_mem *reg_ptr, char *origin_line);

extern void left_var_assignline (char *lvar_str, reg_set *reg_len_ptr,
                                 reg_mem *reg_ptr, char *origin_line);

extern uint8_t parse_compare_sym (char *sym_str, char *origin_line);

extern uint32_t parse_goto (char *right_brace, char *origin_line);

extern bool maybe_reverse (char *clean_line, char *origin_line);

#endif
