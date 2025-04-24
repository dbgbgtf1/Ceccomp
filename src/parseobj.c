#include "parseobj.h"
#include "Main.h"
#include "error.h"
#include "transfer.h"
#include <seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// this is used in if line
// if ($A == X86_64)
// if ($A == write)
// if ($A > 0xffffffff)
uint32_t
ParseVal (char *rval_str, uint32_t arch, char *Line)
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

  else
    {
      char *end;
      rval = strtol (rval_str, &end, 0);
      if (rval_str == end)
        PEXIT ("invalid right value: %s", Line);
    }
  return rval;
}

// this is used in assign line
// $A = $low args[0]
// $A = $syscall_nr
uint32_t
ParseVar (char *rvar_str, seccomp_data *data, char *Line)
{
  uint32_t data_offset;
  if ((data_offset = STR2ABS (rvar_str)) == -1)
    PEXIT ("invalid right variable: %s", Line);
  return *(uint32_t *)((char *)data + data_offset);
}

// this is used both in assign and if lines
// $A
// $mem[0x0]
void
ParseReg (char *reg_str, reg_set *reg_set, reg_mem *reg_ptr, char *Line)
{
  uint32_t reg_offset = STR2REG (reg_str);
  if (reg_offset == -1)
    PEXIT ("invalid left variable: %s", Line);

  if (reg_offset > offsetof (reg_mem, X))
    reg_set->reg_len = strlen ("$mem[0x0]");
  else
    reg_set->reg_len = strlen ("$A");

  reg_set->reg_ptr = (uint32_t *)((char *)reg_ptr + reg_offset);
}

uint32_t
ParseSym (char *sym, char *Line)
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

  PEXIT ("invalid operator: %s", Line);
}

uint32_t
ParseJmp (char *right_brace, char *Line)
{
  if (!STARTWITH (right_brace, ")goto"))
    PEXIT ("use 'goto' after ( ): %s", Line);

  char *jt_str = right_brace + strlen (")goto");
  char *jf_str = NULL;
  uint8_t jt = 0;
  uint8_t jf = 0;

  jt = strtol (jt_str, &jf_str, 10);
  if (jt == 0)
    PEXIT ("line num to go after goto: %s", Line);

  if (STARTWITH (jf_str, ",elsegoto"))
    {
      jf_str += strlen (",elsegoto");
      jf = strtol (jf_str, NULL, 10);
      if (jf == 0)
        PEXIT ("line num to go after else goto: %s", Line);
    }

  return JMPSET (jt, jf);
}

bool
MaybeReverse (char *after_if, char *Line)
{
  if (*after_if == '!')
    {
      if (*(after_if + 1) == '(')
        return true;
      PEXIT ("use if!( ) to reverse the condition: %s", Line);
    }
  else if (*after_if == '(')
    return false;
  else
    PEXIT ("use if( ) to wrap condition : %s", Line);
}
