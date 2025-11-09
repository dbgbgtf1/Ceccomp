#include "parseobj.h"
#include "asm.h"
#include "color.h"
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

static char *origin_line;
static uint32_t idx;

void
set_error_log (char *origin, uint32_t pc)
{
  origin_line = origin;
  idx = pc;
}

uint32_t
syscall_name (char *str, uint32_t arch)
{
  char *syscall_name = strndup (str, strchr (str, ')') - str);
  uint32_t ret = seccomp_syscall_resolve_name_arch (arch, syscall_name);
  free (syscall_name);
  if (ret != (uint32_t)__NR_SCMP_ERROR)
    return ret;
  else
    return -1;
}
// this is used in if line, right value only
// if ($A == X86_64)
// if ($A == X86_64.open)
// if ($A > $X)
// if ($A == write)
// if ($A > 0xffffffff)
uint32_t
right_val_ifline (char *rval_str, reg_mem *reg, uint32_t arch)
{
  int32_t rval = syscall_name (rval_str, arch);
  if (rval != -1)
    return rval;
  // write

  if (STARTWITH (rval_str, "$X"))
    return reg->X;
  // $X

  rval = STR2ARCH (rval_str);
  if (rval != -1)
    {
      char *syscall_str = STRAFTER (rval_str, ".");
      if (!syscall_str)
        return rval;
      // X86_64

      rval = syscall_name (syscall_str, rval);
      if (rval == -1)
        error (FORMAT " %s: %s", idx, INVALID_RIGHT_VAL, origin_line);
      else
        return rval;
      // X86_64.open
    }

  char *end;
  rval = strtoul (rval_str, &end, 0);
  if (rval_str != end)
    return rval;
  // 0xffffffff

  error (FORMAT " %s: %s", idx, INVALID_RIGHT_VAL, origin_line);
}

// this is used in assign line, right value only
// $A = $mem[0x0]
// $A = $mem[0]
// $A = 0x100
// $X = $scmp_data_len
// $X = $syscall_nr (this is wrong! $X can't be load with abs)
uint32_t
right_val_assignline (FILE *s_output_fp, char *rval_str, reg_mem *reg_ptr)
{
  uint32_t offset;
  char *print_fmt = "";
  uint32_t rval = 0;

  offset = STR2REG (rval_str);
  if (offset != (uint32_t)-1)
    {
      print_fmt = BRIGHT_YELLOW ("%s");
      rval = *(uint32_t *)((char *)reg_ptr + offset);
      goto print_rval;
    }

  offset = STR2MEM (rval_str);
  if (offset != (uint32_t)-1)
    {
      print_fmt = BRIGHT_YELLOW ("%s");
      rval = *(uint32_t *)((char *)reg_ptr + offset);
      if (rval == (uint32_t)ARG_INIT_VAL)
        error (FORMAT " %s: %s", idx, ST_MEM_BEFORE_LD, origin_line);
      goto print_rval;
    }

  char *end = NULL;
  rval = strtoul (rval_str, &end, 0);
  if (end != rval_str)
    {
      print_fmt = CYAN ("%s");
      goto print_rval;
    }

  if (!strcmp (rval_str, SCMP_DATA_LEN))
    {
      rval = 0x40;
      print_fmt = BRIGHT_BLUE ("%s");
      goto print_rval;
    }

  error (FORMAT " %s: %s", idx, INVALID_RIGHT_VAL, origin_line);
print_rval:
  fprintf (s_output_fp, print_fmt, rval_str);
  return rval;
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
    error (FORMAT " %s: %s", idx, INVALID_LEFT_VAR, origin_line);
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

  error (FORMAT " %s: %s", idx, INVALID_OPERATOR, origin_line);
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

  error (FORMAT " %s: %s", idx, INVALID_OPERATOR, origin_line);
}

uint32_t
parse_goto (char *goto_str)
{
  if (!STARTWITH (goto_str, "goto"))
    error (FORMAT " %s: %s", idx, GOTO_AFTER_CONDITION, origin_line);

  char *jt_str = goto_str + strlen ("goto");
  char *jf_str = NULL;
  uint16_t jt = 0;
  uint16_t jf = 0;

  jt = strtoul (jt_str, &jf_str, 10);
  if (jf_str == jt_str)
    error (FORMAT " %s: %s", idx, LINE_NR_AFTER_GOTO, origin_line);

  if (STARTWITH (jf_str, ",elsegoto"))
    {
      jf_str += strlen (",elsegoto");
      jf = strtoul (jf_str, &jt_str, 10);
      if (jt_str == jf_str)
        error (FORMAT " %s: %s", idx, LINE_NR_AFTER_ELSE, origin_line);
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
    error (FORMAT " %s: %s", idx, INVALID_IF, origin_line);
}
