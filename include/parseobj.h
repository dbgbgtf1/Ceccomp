#ifndef PARSEOBJ
#define PARSEOBJ

#include "Main.h"
#include "emu.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct
{
  uint8_t reg_len;
  uint32_t *reg_ptr;
} reg_set;

#define GETJT(jmpset) ((jmpset & 0xff00) >> 8)
#define GETJF(jmpset) (jmpset & 0x00ff)
#define JMPSET(jt, jf) ((jt << 8) | jf)

#define GETSYMLEN(symset) ((symset & 0xf0) >> 4)
#define GETSYMIDX(symset) (symset & 0xf)

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

uint32_t ParseVal (char *val_str, uint32_t arch, char *Line);

uint32_t ParseVar (char *rvar_str, seccomp_data *data, char *Line);

void ParseReg (char *reg_str, reg_set *reg_len_ptr, reg_mem *reg_ptr,
               char *Line);

uint32_t ParseSym (char *sym, char *Line);

uint32_t ParseJmp (char *right_brace, char *Line);

bool MaybeReverse (char *after_if, char *Line);

#endif
