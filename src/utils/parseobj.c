#include "parseobj.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include "parseargs.h"
#include "transfer.h"
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// this is used in if line, right value only
// if ($A == X86_64)
// if ($A > $X)
// if ($A == write)
// if ($A > 0xffffffff)
uint32_t
right_val_ifline (char *rval_str, reg_mem *reg, uint32_t arch)
{
  uint32_t rval = STR2ARCH (rval_str);
  if (rval != (uint32_t)-1)
    return rval;

  if (STARTWITH (rval_str, "$X"))
    return reg->X;

  char *syscall_name = strndup (rval_str, strchr (rval_str, ')') - rval_str);
  rval = seccomp_syscall_resolve_name_arch (arch, syscall_name);
  free (syscall_name);
  if (rval != (uint32_t)__NR_SCMP_ERROR)
    return rval;

  char *end;
  rval = strtoul (rval_str, &end, 0);
  if (rval_str != end)
    return rval;

  log_err (INVALID_RIGHT_VAL);
}

// this is used in assign line, right value only
// $A = $mem[0x0]
// $A = $mem[0]
// $A = 0x100
// $X = $syscall_nr (this is wrong! $X can't be load with abs)
uint32_t
right_val_assignline (char *rval_str, reg_mem *reg_ptr)
{
  uint32_t offset;

  offset = STR2REG (rval_str);
  if (offset != (uint32_t)-1)
    return *(uint32_t *)((char *)reg_ptr + offset);

  offset = STR2MEM (rval_str);
  if (offset != (uint32_t)-1)
    {
      uint32_t retval = *(uint32_t *)((char *)reg_ptr + offset);
      if (retval == (uint32_t)ARG_INIT_VAL)
        log_err (ST_MEM_BEFORE_LD);
      return retval;
    }

  char *end = NULL;
  uint32_t rval = strtoul (rval_str, &end, 0);
  if (end != rval_str)
    return rval;

  log_err (INVALID_RIGHT_VAL);
}

// this is used in assign line, left value only
// $A
// $X
// $mem[0x0]
// $mem[0]
void
left_val_assignline (char *lval_str, reg_set *reg_set, reg_mem *reg_ptr)
{
  uint32_t reg_offset = STR2REG (lval_str);
  if (reg_offset != (uint32_t)-1)
    {
      reg_set->reg_len = strlen ("$A");
      reg_set->reg_ptr = (uint32_t *)((char *)reg_ptr + reg_offset);
      return;
    }

  reg_offset = STR2MEM (lval_str);
  if (reg_offset != (uint32_t)-1)
    {
      reg_set->reg_len = (size_t)strchr (lval_str, ']') - (size_t)lval_str + 1;
      reg_set->reg_ptr = (uint32_t *)((char *)reg_ptr + reg_offset);
      return;
    }
  else
    log_err (INVALID_LEFT_VAR);
}

// return JMP ENUM, GETSYMLEN and GETSYMIDX to use it
// take a look at JMP ENUM, GETSYMLEN and GETSYMIDX
uint8_t
parse_cmp_sym (char *sym_str)
{
  if (!strncmp (sym_str, "==", 2))
    return CMP_EQ;
  else if (!strncmp (sym_str, ">=", 2))
    return CMP_GE;
  else if (!strncmp (sym_str, ">", 1))
    return CMP_GT;
  else if (!strncmp (sym_str, "&", 1))
    return CMP_AD;

  else if (!strncmp (sym_str, "!=", 2))
    return CMP_NE;
  else if (!strncmp (sym_str, "<=", 2))
    return CMP_LE;
  else if (!strncmp (sym_str, "<", 1))
    return CMP_LT;

  log_err (INVALID_OPERATOR);
}

uint8_t
parse_alu_sym (char *cmp_str)
{
  if (!strncmp (cmp_str, "&=", 2))
    return ALU_AN;
  else if (!strncmp (cmp_str, "+=", 2))
    return ALU_AD;
  else if (!strncmp (cmp_str, "-=", 2))
    return ALU_SU;
  else if (!strncmp (cmp_str, "*=", 2))
    return ALU_ML;
  else if (!strncmp (cmp_str, "/=", 2))
    return ALU_DV;
  else if (!strncmp (cmp_str, "|=", 2))
    return ALU_OR;
  else if (!strncmp (cmp_str, "^=", 2))
    return ALU_ML;
  else if (!strncmp (cmp_str, "<<=", 3))
    return ALU_LS;
  else if (!strncmp (cmp_str, ">>=", 3))
    return ALU_RS;

  log_err (INVALID_OPERATOR);
}

uint32_t
parse_goto (char *goto_str)
{
  if (!STARTWITH (goto_str, "goto"))
    log_err (GOTO_AFTER_CONDITION);

  char *jt_str = goto_str + strlen ("goto");
  char *jf_str = NULL;
  uint16_t jt = 0;
  uint16_t jf = 0;

  jt = strtoul (jt_str, &jf_str, 10);
  if (jf_str == jt_str)
    log_err (LINE_NR_AFTER_GOTO);

  if (STARTWITH (jf_str, ",elsegoto"))
    {
      jf_str += strlen (",elsegoto");
      jf = strtoul (jf_str, &jt_str, 10);
      if (jt_str == jf_str)
        log_err (LINE_NR_AFTER_ELSE);
    }

  return JMPSET (jt, jf);
}

// this is used in jmp only
// BPF JMP always compare other with $A
// so make sure this startwith "if($A" or "if!($A"
bool
maybe_reverse (char *clean_line)
{
  if (STARTWITH (clean_line, "if($A"))
    return false;
  else if (STARTWITH (clean_line, "if!($A"))
    return true;
  else
    log_err (INVALID_IF);
}
