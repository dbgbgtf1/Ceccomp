#include "parseobj.h"
#include "Main.h"
#include "emu.h"
#include "error.h"
#include "transfer.h"
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

// this is used in if line
// if ($A == X86_64)
// if ($A == write)
// if ($A > 0xffffffff)
// if ($A > $X)
uint32_t
ParseVal (char *rval_str, reg_mem *reg, uint32_t arch, char *origin_line)
{
  uint32_t rval;
  if ((rval = STR2ARCH (rval_str)) != -1)
    return rval;

  char *syscall_name = strndup (rval_str, strchr (rval_str, ')') - rval_str);
  if ((rval = seccomp_syscall_resolve_name_arch (arch, syscall_name))
      != __NR_SCMP_ERROR)
    {
      free (syscall_name);
      return rval;
    }
  free (syscall_name);
  if (STARTWITH (rval_str, "$X"))
    return reg->X;

  char *end;
  rval = strtol (rval_str, &end, 0);
  if (rval_str == end)
    PEXIT ("invalid right value: %s", origin_line);
  return rval;
}

// this is used in assign line, right value only
// $A = $low args[0]
// $A = $syscall_nr
// $A = $mem[0x0]
// $A = $mem[0]
// $A = 0x100
uint32_t
ParseVar (char *rvar_str, seccomp_data *data, reg_mem *reg_ptr,
          char *origin_line)
{
  uint32_t offset;
  if ((offset = STR2ABS (rvar_str)) != -1)
    return *(uint32_t *)((char *)data + offset);
  else if ((offset = STR2REG (rvar_str)) != -1)
    return *(uint32_t *)((char *)reg_ptr + offset);

  char *end = NULL;
  uint32_t rval = strtol (rvar_str, &end, 0);
  if (end != rvar_str)
    return rval;
  PEXIT ("invalid right variable: %s", origin_line);
}

// this is used both in assign and if lines, left value only
// $A
// $mem[0x0]
// $mem[0]
void
ParseReg (char *reg_str, reg_set *reg_set, reg_mem *reg_ptr, char *origin_line)
{
  uint32_t reg_offset = STR2REG (reg_str);
  if (reg_offset == -1)
    PEXIT ("invalid left variable: %s", origin_line);

  if (reg_offset > offsetof (reg_mem, X))
    reg_set->reg_len = (size_t)strchr (reg_str, ']') - (size_t)reg_str + 1;
  else
    reg_set->reg_len = strlen ("$A");

  reg_set->reg_ptr = (uint32_t *)((char *)reg_ptr + reg_offset);
}

// return JMP ENUM, GETSYMLEN and GETSYMIDX to use it
// take a look at JMP ENUM, GETSYMLEN and GETSYMIDX
uint8_t
ParseSym (char *sym, char *origin_line)
{
  if (!strncmp (sym, "==", 2))
    return SYM_EQ;
  else if (!strncmp (sym, ">=", 2))
    return SYM_GE;
  else if (!strncmp (sym, ">", 1))
    return SYM_GT;
  else if (!strncmp (sym, "&", 1))
    return SYM_AD;

  else if (!strncmp (sym, "!=", 2))
    return SYM_NE;
  else if (!strncmp (sym, "<=", 2))
    return SYM_LE;
  else if (!strncmp (sym, "<", 1))
    return SYM_LT;

  PEXIT (INVALID_OPERATOR ": %s", origin_line);
}

uint16_t
ParseJmp (char *right_brace, char *origin_line)
{
  if (!STARTWITH (right_brace, ")goto"))
    PEXIT ("use 'goto' after ( ): %s", origin_line);

  char *jt_str = right_brace + strlen (")goto");
  char *jf_str = NULL;
  uint8_t jt = 0;
  uint8_t jf = 0;

  jt = strtol (jt_str, &jf_str, 10);
  if (jt == 0)
    PEXIT ("line num to go after goto: %s", origin_line);

  if (STARTWITH (jf_str, ",elsegoto"))
    {
      jf_str += strlen (",elsegoto");
      jf = strtol (jf_str, NULL, 10);
      if (jf == 0)
        PEXIT ("line num to go after else goto: %s", origin_line);
    }

  return JMPSET (jt, jf);
}

// this is used in jmp only
// BPF JMP always compare other with $A
// so make sure this startwith "if($A" or "if!($A"
bool
MaybeReverse (char *clean_line, char *origin_line)
{
  if (STARTWITH (clean_line, "if($A"))
    return false;
  else if (STARTWITH (clean_line, "if!($A"))
    return false;
  else
    PEXIT (INVALID_IF ": %s", origin_line);
}
