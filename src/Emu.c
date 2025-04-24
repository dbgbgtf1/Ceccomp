#include "emu.h"
#include "Main.h"
#include "color.h"
#include "error.h"
#include "parseobj.h"
#include "preasm.h"
#include "transfer.h"
#include <fcntl.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LIGHTCOLORPRINTF(str, ...) printf (LIGHTCOLOR (str "\n"), __VA_ARGS__)

bool
isStateTrue (uint32_t lval, uint32_t symidx, uint32_t rval)
{
  switch (symidx)
    {
    case GETSYMIDX (SYM_EQ):
      return (lval == rval);
    case GETSYMIDX (SYM_GT):
      return (lval > rval);
    case GETSYMIDX (SYM_GE):
      return (lval >= rval);
    case GETSYMIDX (SYM_LE):
      return (lval <= rval);
    case GETSYMIDX (SYM_AD):
      return (lval & rval);
    case GETSYMIDX (SYM_LT):
      return (lval > rval);
    case GETSYMIDX (SYM_NE):
      return (lval != rval);
    default:
      PEXIT ("unknown symidx: %d", symidx);
    }
}

bool
ParseCondition (char *left_brace, reg_mem *reg, seccomp_data *data, char *Line)
{
  char *lvar = left_brace + strlen ("(");

  reg_set lvarset;
  ParseReg (lvar, &lvarset, reg, Line);
  uint8_t lvar_len = lvarset.reg_len;
  uint32_t *reg_ptr = lvarset.reg_ptr;

  char *sym = lvar + lvar_len;
  uint8_t symset = ParseSym (sym, Line);
  uint8_t symlen = GETSYMLEN (symset);
  uint8_t symidx = GETSYMIDX (symset);

  char *rvar = sym + symlen;
  uint32_t rval = ParseVal (rvar, data->arch, Line);

  printf (BLUE_LS, lvar_len, lvar);
  printf (" %.*s ", symlen, sym);
  printf (BLUE_LS, (uint32_t)(strchr (rvar, ')') - rvar), rvar);

  return isStateTrue (*reg_ptr, GETSYMIDX (symset), rval);
}

uint32_t
IfLine (char *Line, reg_mem *reg, seccomp_data *data)
{
  char *left_brace = Line + strlen ("if");
  bool reverse = MaybeReverse (left_brace, Line);
  if (reverse)
    {
      left_brace += 1;
      printf ("%s", "if !(");
    }
  else
    printf ("%s", "if (");

  char *right_brace = strchr (left_brace, ')');
  if (right_brace == NULL)
    PEXIT ("use if( ) to wrap condition: %s", Line);

  bool condition;
  condition = ParseCondition (left_brace, reg, data, Line);

  uint32_t jmpset = ParseJmp (right_brace, Line);
  uint16_t jf = GETJF (jmpset);
  uint16_t jt = GETJT (jmpset);

  if (jf != 0)
    printf (") goto" FORMAT ", else goto " FORMAT "\n", jt, jf);
  else
    printf (") goto " FORMAT "\n", jt);

  if (condition && reverse)
    return jf;
  else if (!condition && !reverse)
    return jf;
  else
    return jt;
}

void
AssignLine (char *Line, reg_mem *reg, seccomp_data *data)
{
  reg_set lvar;
  ParseReg (Line, &lvar, reg, Line);
  uint8_t lvar_len = lvar.reg_len;
  uint32_t *lvar_ptr = lvar.reg_ptr;

  if (*(Line + lvar_len) != '=')
    PEXIT ("invalid operator in assign: %s", Line);

  char *rvar = Line + lvar_len + 1;
  uint32_t rval = ParseVar (rvar, data, Line);

  *lvar_ptr = rval;
  printf (BLUE_LS " = " PURPLE_S "\n", lvar_len, Line, rvar);
}

void
RetLine (char *Line)
{
  char *retval_str = STRAFTER (Line, "return");
  uint32_t retval = STR2RETVAL (retval_str);
  retval_str = RETVAL2STR (retval);

  printf ("return %s\n", retval_str);
}

void
ResolveLines (FILE *fp, seccomp_data *data)
{
  char *Line = NULL;
  reg_mem *reg = malloc (sizeof (reg_mem));

  uint32_t read_idx = 0;
  uint32_t actual_idx = 0;

  while ((Line = PreAsm (fp)) != NULL)
    {
      read_idx++;
      if (read_idx < actual_idx)
        {
          LIGHTCOLORPRINTF (FORMAT ": %s", read_idx, Line);
          continue;
        }
      printf (FORMAT ": ", read_idx);
      actual_idx++;

      if (STARTWITH (Line, "if"))
        actual_idx = IfLine (Line, reg, data);
      else if (STARTWITH (Line, "ret"))
        RetLine (Line);
      else if (*Line == '$')
        AssignLine (Line, reg, data);
      else
        PEXIT ("invalid Line: %s", Line);
      // PreAsm return correct Lines
      // if Line == '\0', it doesn't matter
    }

  free (reg);
}

void
emu (int argc, char *argv[])
{
  // argv[0] = dump-result
  // argv[1] = arch
  // argv[2] = nr
  // emu need these args to run at least

  if (argc < 3)
    PEXIT (
        "%s",
        "No enough args\nusage: Ceccomp emu dump-result arch nr [ argv[0] - "
        "argv[5] ] (default as 0)");

  FILE *fp = fopen (argv[0], "r");
  if (!fp)
    PEXIT ("unable to open result file: %s", argv[0]);

  seccomp_data *data = malloc (sizeof (seccomp_data));

  data->arch = STR2ARCH (argv[1]);
  if (data->arch == -1)
    PEXIT ("invalid arch: %s\nsupport arch: X86 X86_64 X32 ARM AARCH64 MIPS "
           "MIPSEL MIPSEL64 MIPSEL64N32 PARISC PARISC64 PPC PPC64 PPC64LE "
           "S390 S390X RISCV64",
           argv[1]);

  char *end = NULL;
  data->nr = seccomp_syscall_resolve_name_arch (data->arch, argv[2]);
  if (data->nr == __NR_SCMP_ERROR)
    {
      data->nr = strtol (argv[2], &end, 0);
      if ((data->nr == 0) && (argv[2] == end))
        PEXIT ("invalid syscall nr: %s", argv[2]);
    }

  for (int i = 3; i < argc; i++)
    {
      data->args[i] = strtol (argv[i], &end, 0);
      if ((data->args[i]) && (argv[i] == end))
        PEXIT ("invaild syscall args: %s", argv[i]);
    }

  ResolveLines (fp, data);

  free (data);
}
