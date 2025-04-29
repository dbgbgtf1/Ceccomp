#include "emu.h"
#include "color.h"
#include "error.h"
#include "main.h"
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

static bool
is_state_true (uint32_t A, uint32_t sym_enum, uint32_t rval)
{
  switch (sym_enum)
    {
    case SYM_EQ:
      return (A == rval);
    case SYM_GT:
      return (A > rval);
    case SYM_GE:
      return (A >= rval);
    case SYM_LE:
      return (A <= rval);
    case SYM_AD:
      return (A & rval);
    case SYM_LT:
      return (A < rval);
    case SYM_NE:
      return (A != rval);
    default:
      PEXIT (INVALID_SYMENUM ": %d", sym_enum);
    }
}

static bool
emu_condition (char *sym_str, reg_mem *reg, seccomp_data *data,
               char *origin_line)
{
  uint8_t sym_enum = parse_compare_sym (sym_str, origin_line);
  uint8_t symlen = GETSYMLEN (sym_enum);

  char *rvar = sym_str + symlen;
  uint32_t rval = right_val_ifline (rvar, reg, data->arch, origin_line);

  printf (BLUE_A);
  printf (" %.*s ", symlen, sym_str);
  printf (BLUE_LS, (uint32_t)(strchr (rvar, ')') - rvar), rvar);

  return is_state_true (reg->A, sym_enum, rval);
}

static uint32_t
emu_if_line (line_set *Line, reg_mem *reg, seccomp_data *data)
{
  char *clean_line = Line->clean_line;
  char *origin_line = Line->origin_line;

  char *sym_str;
  bool reverse = maybe_reverse (clean_line, origin_line);
  if (reverse)
    {
      sym_str = clean_line + strlen ("if!($A");
      printf ("if!(");
    }
  else
    {
      sym_str = clean_line + strlen ("if($A");
      printf ("if!(");
    }

  bool condition;
  condition = emu_condition (sym_str, reg, data, origin_line);

  char *right_brace = strchr (sym_str, ')');
  if (right_brace == NULL)
    PEXIT ("use if( ) to wrap condition: %s", origin_line);

  uint32_t jmp_set = parse_goto (right_brace, origin_line);
  uint8_t jf = GETJF (jmp_set);
  uint8_t jt = GETJT (jmp_set);

  if (jf != 0)
    printf (") goto " FORMAT ", else goto " FORMAT "\n", jt, jf);
  else
    printf (") goto " FORMAT "\n", jt);

  if (condition && reverse)
    return jf;
  else if (!condition && !reverse)
    return jf;
  else
    return jt;
}

static void
emu_assign_line (line_set *Line, reg_mem *reg, seccomp_data *data)
{
  char *clean_line = Line->clean_line;
  char *origin_line = Line->origin_line;

  reg_set lvar;
  left_var_assignline (clean_line, &lvar, reg, origin_line);
  uint8_t lvar_len = lvar.reg_len;
  uint32_t *lvar_ptr = lvar.reg_ptr;

  if (*(clean_line + lvar_len) != '=')
    PEXIT ("invalid operator in assign: %s", origin_line);

  char *rvar = clean_line + lvar_len + 1;
  uint32_t rval = right_var_assignline (rvar, data, reg, origin_line);

  *lvar_ptr = rval;
  printf (BLUE_LS " = " BLUE_S "\n", lvar_len, clean_line, rvar);
}

static uint32_t
emu_ret_line (line_set *Line)
{
  char *retval_str = STRAFTER (Line->clean_line, "return");
  uint32_t retval = STR2RETVAL (retval_str);
  if (retval == -1)
    PEXIT ("invalid return value: %s", Line->origin_line);

  retval_str = RETVAL2STR (retval);

  printf ("return %s\n", retval_str);

  return 0xffffffff;
}

static void
clear_color (char *origin_line)
{
  char *color_start = NULL;
  char *color_end = NULL;

  while ((color_start = strchr (origin_line, '\e')) != NULL)
    {
      color_end = strchr (color_start, 'm');
      sprintf (color_start, "%s", color_end + 1);
    }
}

static void
emu_lines (FILE *fp, seccomp_data *data)
{
  line_set Line = { NULL, NULL };
  reg_mem *reg = malloc (sizeof (reg_mem));

  char *origin_line;
  char *clean_line;
  for (uint32_t read_idx = 1, actual_idx = 1;
       pre_asm (fp, &Line), Line.origin_line != NULL; read_idx++)
    {
      origin_line = Line.origin_line;
      clean_line = Line.clean_line;

      if (read_idx < actual_idx)
        {
          clear_color (origin_line);
          LIGHTCOLORPRINTF (FORMAT ": %s", read_idx, origin_line);
          free (clean_line);
          continue;
        }
      printf (FORMAT ": ", read_idx);
      actual_idx++;

      if (STARTWITH (clean_line, "if"))
        actual_idx = emu_if_line (&Line, reg, data);
      else if (STARTWITH (clean_line, "return"))
        actual_idx = emu_ret_line (&Line);
      else if (*clean_line == '$')
        emu_assign_line (&Line, reg, data);
      else
        PEXIT ("invalid Line: %s", origin_line);

      free (clean_line);
    }

  free (reg);
}

void
emu (int argc, char *argv[])
{
  if (argc < 3)
    PEXIT ("%s\n%s\n", NOT_ENOUGH_ARGS, EMU_HINT);

  seccomp_data *data = malloc (sizeof (seccomp_data));
  data->arch = STR2ARCH (argv[0]);
  if (data->arch == -1)
    PEXIT("%s\n%s\n", INVALID_ARCH, SUPPORT_ARCH);

  FILE *fp = fopen (argv[1], "r");
  if (fp == NULL)
    PEXIT ("unable to open result file: %s", argv[0]);

  char *end = NULL;
  data->nr = seccomp_syscall_resolve_name_arch (data->arch, argv[2]);
  if (data->nr == __NR_SCMP_ERROR)
    {
      data->nr = strtol (argv[2], &end, 0);
      if (argv[2] == end)
        PEXIT (INVALID_SYSNR ": %s\n", argv[2]);
    }

  for (int i = 3; i < argc; i++)
    {
      data->args[i] = strtol (argv[i], &end, 0);
      if (argv[i] == end)
        PEXIT (INVALID_SYS_ARGS ": %s\n", argv[i]);
    }

  emu_lines (fp, data);

  free (data);
}
