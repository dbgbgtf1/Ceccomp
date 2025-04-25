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
#include <stdio.h>
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
ParseCondition (char *left_brace, reg_mem *reg, seccomp_data *data,
                char *origin_line)
{
  char *lvar = left_brace + strlen ("(");

  reg_set lvar_set;
  ParseReg (lvar, &lvar_set, reg, origin_line);
  uint8_t lvar_len = lvar_set.reg_len;
  uint32_t *reg_ptr = lvar_set.reg_ptr;

  char *sym = lvar + lvar_len;
  uint8_t sym_set = ParseSym (sym, origin_line);
  uint8_t symlen = GETSYMLEN (sym_set);
  uint8_t symidx = GETSYMIDX (sym_set);

  char *rvar = sym + symlen;
  uint32_t rval = ParseVal (rvar, data->arch, origin_line);

  printf (BLUE_LS, lvar_len, lvar);
  printf (" %.*s ", symlen, sym);
  printf (BLUE_LS, (uint32_t)(strchr (rvar, ')') - rvar), rvar);

  return isStateTrue (*reg_ptr, GETSYMIDX (sym_set), rval);
}

uint32_t
IfLine (line_set *Line, reg_mem *reg, seccomp_data *data)
{
  char *left_brace = Line->clean_line + strlen ("if");
  bool reverse = MaybeReverse (left_brace, Line->origin_line);
  if (reverse)
    {
      left_brace += 1;
      printf ("%s", "if !(");
    }
  else
    printf ("%s", "if (");

  char *right_brace = strchr (left_brace, ')');
  if (right_brace == NULL)
    PEXIT ("use if( ) to wrap condition: %s", Line->origin_line);

  bool condition;
  condition = ParseCondition (left_brace, reg, data, Line->origin_line);

  uint32_t jmp_set = ParseJmp (right_brace, Line->origin_line);
  uint16_t jf = GETJF (jmp_set);
  uint16_t jt = GETJT (jmp_set);

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
AssignLine (line_set *Line, reg_mem *reg, seccomp_data *data)
{
  reg_set lvar;
  ParseReg (Line->clean_line, &lvar, reg, Line->origin_line);
  uint8_t lvar_len = lvar.reg_len;
  uint32_t *lvar_ptr = lvar.reg_ptr;

  if (*(Line->clean_line + lvar_len) != '=')
    PEXIT ("invalid operator in assign: %s", Line->origin_line);

  char *rvar = Line->clean_line + lvar_len + 1;
  uint32_t rval = ParseVar (rvar, data, Line->origin_line);

  *lvar_ptr = rval;
  printf (BLUE_LS " = " BLUE_S "\n", lvar_len, Line->clean_line, rvar);
}

uint32_t
RetLine (line_set *Line)
{
  char *retval_str = STRAFTER (Line->clean_line, "return");
  uint32_t retval = STR2RETVAL (retval_str);
  if (retval == -1)
    PEXIT ("invalid return value: %s", Line->origin_line);

  retval_str = RETVAL2STR (retval);

  printf ("return %s\n", retval_str);

  return 0xffffffff;
}

void
ResolveLines (FILE *fp, seccomp_data *data)
{
  line_set Line = { NULL, NULL };
  reg_mem *reg = malloc (sizeof (reg_mem));

  uint32_t read_idx = 0;
  uint32_t actual_idx = 0;

  char *origin_line;
  char *clean_line;
  while (PreAsm(fp, &Line), Line.origin_line != NULL)
    {
      origin_line = Line.origin_line;
      clean_line = Line.clean_line;

      read_idx++;
      if (read_idx < actual_idx)
        {
          LIGHTCOLORPRINTF (FORMAT ": %s", read_idx, origin_line);
          free (clean_line);
          continue;
        }
      printf (FORMAT ": ", read_idx);
      actual_idx++;

      if (STARTWITH (clean_line, "if"))
        actual_idx = IfLine (&Line, reg, data);
      else if (STARTWITH (clean_line, "ret"))
        actual_idx = RetLine (&Line);
      else if (*clean_line == '$')
        AssignLine (&Line, reg, data);
      else
        PEXIT ("invalid Line: %s", origin_line);

      free (clean_line);
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
