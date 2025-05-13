#include "emu.h"
#include "color.h"
#include "error.h"
#include "main.h"
#include "parseargs.h"
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

static bool is_state_true (uint32_t A, uint32_t sym_enum, uint32_t rval);

static bool emu_condition (char *sym_str, reg_mem *reg, seccomp_data *data,
                           char *origin_line);

static void emu_assign_line (line_set *Line, reg_mem *reg, seccomp_data *data);

static uint32_t emu_ret_line (line_set *Line);

static uint32_t emu_if_line (line_set *Line, reg_mem *reg, seccomp_data *data);

static void clear_color (char *origin_line);

static void emu_lines (FILE *fp, seccomp_data *data);

static bool
is_state_true (uint32_t A, uint32_t cmp_enum, uint32_t rval)
{
  switch (cmp_enum)
    {
    case CMP_EQ:
      return (A == rval);
    case CMP_GT:
      return (A > rval);
    case CMP_GE:
      return (A >= rval);
    case CMP_LE:
      return (A <= rval);
    case CMP_AD:
      return (A & rval);
    case CMP_LT:
      return (A < rval);
    case CMP_NE:
      return (A != rval);
    default:
      PEXIT (INVALID_CMPENUM ": %d", cmp_enum);
    }
}

static bool
emu_condition (char *sym_str, reg_mem *reg, seccomp_data *data,
               char *origin_line)
{
  uint8_t sym_enum = parse_cmp_sym (sym_str, origin_line);
  uint8_t sym_len = GETSYMLEN (sym_enum);

  char *rval_str = sym_str + sym_len;
  uint32_t rval = right_val_ifline (rval_str, reg, data->arch, origin_line);

  printf (BLUE_A);
  printf (" %.*s ", sym_len, sym_str);
  printf (BLUE_LS, (uint32_t)(strchr (rval_str, ')') - rval_str), rval_str);

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
      printf ("if(");
    }

  bool condition;
  condition = emu_condition (sym_str, reg, data, origin_line);

  char *right_brace = strchr (sym_str, ')');
  if (right_brace == NULL)
    PEXIT (BRACE_WRAP_CONDITION ": %s", origin_line);

  uint32_t jmp_set = parse_goto (right_brace + 1, origin_line);
  uint16_t jf = GETJF (jmp_set);
  uint16_t jt = GETJT (jmp_set);

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

  reg_set lval;
  left_val_assignline (clean_line, &lval, reg, origin_line);
  uint8_t lval_len = lval.reg_len;
  uint32_t *lval_ptr = lval.reg_ptr;

  if (*(clean_line + lval_len) != '=')
    PEXIT (INVALID_OPERATOR ": %s", origin_line);

  char *rval_str = clean_line + lval_len + 1;
  uint32_t rval = right_val_assignline (rval_str, data, reg, origin_line);

  *lval_ptr = rval;
  printf (BLUE_LS " = " BLUE_S "\n", lval_len, clean_line, rval_str);
}

static uint32_t
emu_ret_line (line_set *Line)
{
  char *retval_str = Line->clean_line + strlen ("return");
  uint32_t retval = STR2RETVAL (retval_str);
  if (retval == -1)
    PEXIT (INVALID_RET_VAL ": %s", Line->origin_line);

  retval_str = RETVAL2STR (retval);
  printf ("return %s\n", retval_str);

  return 0xffffffff;
}

static uint32_t
emu_goto_line (line_set *Line)
{
  char *clean_line = Line->clean_line;
  char *origin_line = Line->origin_line;
  char *end;
  uint32_t jmp_to = strtol (clean_line + strlen ("goto"), &end, 10);

  if (clean_line == end)
    PEXIT (INVALID_NR_AFTER_GOTO ": %s", origin_line);

  printf ("goto %04d\n", jmp_to);
  return jmp_to;
}

static void
emu_do_alu (uint32_t *A_ptr, uint8_t alu_enum, uint32_t rval)
{
  switch (alu_enum)
    {
    case ALU_AN:
      *A_ptr &= rval;
    case ALU_AD:
      *A_ptr += rval;
      return;
    case ALU_SU:
      *A_ptr -= rval;
      return;
    case ALU_ML:
      *A_ptr -= rval;
      return;
    case ALU_DV:
      *A_ptr -= rval;
      return;
    case ALU_OR:
      *A_ptr -= rval;
      return;
    case ALU_NG:
      *A_ptr -= rval;
      return;
    case ALU_LS:
      *A_ptr -= rval;
      return;
    case ALU_RS:
      *A_ptr -= rval;
      return;
    default:
      PEXIT (INVALID_ALUENUM ": %d\n", alu_enum)
    }
}

static void
emu_alu_line (line_set *Line, reg_mem *reg)
{
  char *clean_line = Line->clean_line;
  char *origin_line = Line->origin_line;

  char *sym_str = clean_line + strlen ("$A");
  uint8_t sym_enum = parse_alu_sym (sym_str, origin_line);
  uint8_t sym_len = GETSYMLEN (sym_len);

  uint32_t *A_ptr = &reg->A;

  char *rval_str = sym_str + sym_len;
  uint32_t rval;
  char *end;
  if (!strcmp (rval_str, "$X"))
    rval = reg->X;
  else
    {
      rval = strtol (rval_str, &end, 0);
      if (rval_str == end)
        PEXIT (INVALID_RIGHT ": %s", origin_line);
    }

  emu_do_alu (A_ptr, sym_enum, rval);
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
      else if (STARTWITH (clean_line, "goto"))
        actual_idx += emu_goto_line (&Line);
      else if (STARTWITH (clean_line, "$A") && *(clean_line + 4) == '=')
        emu_alu_line (&Line, reg);
      else if (*clean_line == '$')
        emu_assign_line (&Line, reg, data);
      else
        PEXIT (INVALID_ASM_CODE ": %s", origin_line);

      free (clean_line);
    }

  free (reg);
}

void
emu (int argc, char *argv[])
{
  seccomp_data data;

  char *arch_str = parse_option_mode (argc, argv, "arch");
  data.arch = STR2ARCH (arch_str);

  char *filename = get_arg (argc, argv);
  FILE *fp = fopen (filename, "r");
  if (fp == NULL)
    PEXIT (UNABLE_OPEN_FILE ": %s", filename);

  char *sys_nr_str = get_arg (argc, argv);
  char *end;
  int sys_nr = seccomp_syscall_resolve_name_arch (data.arch, sys_nr_str);
  if (sys_nr == -1)
    {
      sys_nr = strtol (sys_nr_str, &end, 0);
      if (sys_nr_str == end)
        PEXIT ("%s", INVALID_SYSNR);
    }
  data.nr = sys_nr;

  for (int i = 3; i < argc; i++)
    {
      char *arg = get_arg (argc, argv);
      data.args[i] = strtol (arg, &end, 0);
      if (arg == end)
        PEXIT ("%s", INVALID_SYS_ARGS);
    }

  if (argc > 10)
    {
      char *pc = get_arg (argc, argv);
      data.instruction_pointer = strtol (pc, &end, 0);
      if (pc == end)
        PEXIT ("%s", INVALID_PC);
    }

  emu_lines (fp, &data);
}
