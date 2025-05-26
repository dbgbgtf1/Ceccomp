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
#include <sys/types.h>
#include <unistd.h>

#define LIGHTCOLORPRINTF(str, ...) printf (LIGHTCOLOR (str "\n"), __VA_ARGS__)

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
      printf ("if !(");
    }
  else
    {
      sym_str = clean_line + strlen ("if($A");
      printf ("if (");
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

static char *
emu_ret_line (line_set *Line, reg_mem *reg)
{
  char *retval_str = Line->clean_line + strlen ("return");

  if (STARTWITH(retval_str, "$A"))
    return RETVAL2STR(reg->A);

  int32_t retval = STR2RETVAL (retval_str);
  if (retval == -1)
    PEXIT (INVALID_RET_VAL ": %s", Line->origin_line);

  retval_str = RETVAL2STR (retval);
  return retval_str;
}

static uint32_t
emu_goto_line (line_set *Line)
{
  char *clean_line = Line->clean_line;
  char *origin_line = Line->origin_line;
  char *end;
  uint32_t jmp_to = strtoul (clean_line + strlen ("goto"), &end, 10);

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
      return;
    case ALU_AD:
      *A_ptr += rval;
      return;
    case ALU_SU:
      *A_ptr -= rval;
      return;
    case ALU_ML:
      *A_ptr *= rval;
      return;
    case ALU_DV:
      *A_ptr /= rval;
      return;
    case ALU_OR:
      *A_ptr |= rval;
      return;
    case ALU_LS:
      *A_ptr <<= rval;
      return;
    case ALU_RS:
      *A_ptr >>= rval;
      return;
    default:
      PEXIT (INVALID_ALUENUM ": %d\n", alu_enum)
    }
}

static void
emu_alu_neg (reg_mem *reg)
{
  reg->A = -reg->A;
  printf (BLUE_A " = -" BLUE_A "\n");
  return;
}

static void
emu_alu_line (line_set *Line, reg_mem *reg)
{
  char *clean_line = Line->clean_line;
  char *origin_line = Line->origin_line;

  char *sym_str = clean_line + strlen ("$A");
  uint8_t sym_enum = parse_alu_sym (sym_str, origin_line);
  uint8_t sym_len = GETSYMLEN (sym_enum);

  uint32_t *A_ptr = &reg->A;

  char *rval_str = sym_str + sym_len;
  uint32_t rval;
  char *end;
  if (!strcmp (rval_str, "$X"))
    rval = reg->X;
  else
    {
      rval = strtoul (rval_str, &end, 0);
      if (rval_str == end)
        PEXIT (INVALID_RIGHT_VAL ": %s", origin_line);
    }

  emu_do_alu (A_ptr, sym_enum, rval);

  printf (BLUE_A " %.*s " BLUE_S "\n", sym_len, sym_str, rval_str);
}

char *
emu_lines (FILE *read_fp, seccomp_data *data)
{
  line_set Line = { NULL, NULL };
  reg_mem *reg = malloc (sizeof (reg_mem));

  char *origin_line;
  char *clean_line;
  for (uint32_t read_idx = 1, actual_idx = 1;
       pre_asm (read_fp, &Line), Line.origin_line != NULL; read_idx++)
    {
      origin_line = Line.origin_line;
      clean_line = Line.clean_line;

      if (read_idx < actual_idx)
        {
          pre_clear_color (origin_line);
          LIGHTCOLORPRINTF (FORMAT ": %s", read_idx, origin_line);
          free (clean_line);
          continue;
        }
      printf (FORMAT ": ", read_idx);
      actual_idx++;

      if (STARTWITH (clean_line, "if"))
        actual_idx = emu_if_line (&Line, reg, data);
      else if (STARTWITH (clean_line, "return"))
        return emu_ret_line (&Line, reg);
      else if (STARTWITH (clean_line, "goto"))
        actual_idx = emu_goto_line (&Line);
      else if (STARTWITH (clean_line, "$A=-$A"))
        emu_alu_neg (reg);
      else if ((STARTWITH (clean_line, "$") && *(clean_line + 2) == '=')
               || (STARTWITH (clean_line, "$mem[")))
        emu_assign_line (&Line, reg, data);
      else if (STARTWITH (clean_line, "$A"))
        emu_alu_line (&Line, reg);
      else
        PEXIT (INVALID_ASM_CODE ": %s", origin_line);

      free (clean_line);
    }

  free (reg);
  return NULL;
}

int
global_hide_stdout (int filedup2)
{
  int stdout_backup = dup (STDOUT_FILENO);
  if (stdout_backup == -1)
    PERROR ("dup");

  if (dup2 (filedup2, STDOUT_FILENO) == -1)
    PERROR ("global_hide_stdout dup2");

  return stdout_backup;
}

void
global_ret_stdout (int stdout_backup)
{
  if (dup2 (stdout_backup, STDOUT_FILENO) == -1)
    PERROR ("global_ret_stdout dup2")
  close (stdout_backup);
}

void
emulate (ceccomp_args *args)
{
  seccomp_data data = { 0, 0, 0, { 0, 0, 0, 0, 0, 0 } };

  data.arch = args->arch_token;

  if (args->syscall_nr == (char *)ARG_INIT_VAL)
    PEXIT ("%s", INPUT_SYS_NR);

  data.nr
      = seccomp_syscall_resolve_name_arch (args->arch_token, args->syscall_nr);
  if (data.nr == __NR_SCMP_ERROR)
    data.nr = strtoull_check (args->syscall_nr, 0, INVALID_SYSNR);

  for (int i = 0; i < 6; i++)
    data.args[i] = args->sys_args[i];
  data.instruction_pointer = args->ip;

  int stdout_backup = 0;
  char *retval_str = NULL;
  if (args->quiet)
    {
      int null_fd = open ("/dev/null", O_WRONLY);
      stdout_backup = global_hide_stdout (null_fd);
      close (null_fd);
    }

  retval_str = emu_lines (args->read_fp, &data);

  if (stdout_backup != 0)
    global_ret_stdout (stdout_backup);

  printf ("return " BLUE_S "\n", retval_str);
}
