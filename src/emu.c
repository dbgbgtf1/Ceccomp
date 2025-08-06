#include "emu.h"
#include "color.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include "parseargs.h"
#include "parseobj.h"
#include "preasm.h"
#include "transfer.h"
#include <fcntl.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static uint32_t read_idx;
static uint32_t execute_idx;

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
      error (INVALID_CMPENUM ": %d", cmp_enum);
    }
}

static bool
emu_condition (char *sym_str, reg_mem *reg, seccomp_data *data)
{
  uint8_t sym_enum = parse_cmp_sym (sym_str);
  uint8_t sym_len = GETSYMLEN (sym_enum);

  char *rval_str = sym_str + sym_len;
  uint32_t rval = right_val_ifline (rval_str, reg, data->arch);

  printf (CYAN_A);
  printf (" %.*s ", sym_len, sym_str);
  printf (CYAN_LS, (uint32_t)(strchr (rval_str, ')') - rval_str), rval_str);

  return is_state_true (reg->A, sym_enum, rval);
}

static uint32_t
emu_if_line (char *clean_line, reg_mem *reg, seccomp_data *data)
{
  char *sym_str;
  bool reverse = maybe_reverse (clean_line);
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
  condition = emu_condition (sym_str, reg, data);

  char *right_paren = strchr (sym_str, ')');
  if (right_paren == NULL)
    error ("%d %s", read_idx, PAREN_WRAP_CONDITION);

  uint32_t jmp_set = parse_goto (right_paren + 1);
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
emu_assign_line (char *clean_line, reg_mem *reg, seccomp_data *data)
{
  reg_set lval;
  left_val_assignline (clean_line, &lval, reg);
  uint8_t lval_len = lval.reg_len;
  uint32_t *lval_ptr = lval.reg_ptr;

  if (*(clean_line + lval_len) != '=')
    error ("%d %s", read_idx, INVALID_OPERATOR);

  char *rval_str = clean_line + lval_len + 1;

  if (STARTWITH (clean_line, "$A"))
    {
      uint32_t offset = STR2ABS (rval_str);
      if (offset != (uint32_t)-1)
        {
          *lval_ptr = *(uint32_t *)((char *)data + offset);
          printf (CYAN_LS " = " CYAN_S "\n", lval_len, clean_line, rval_str);
          return;
        }
    }

  uint32_t rval = right_val_assignline (rval_str, reg);

  *lval_ptr = rval;
  printf (CYAN_LS " = " CYAN_S "\n", lval_len, clean_line, rval_str);
}

static char *
emu_ret_line (char *clean_line, reg_mem *reg)
{
  char *retval_str = clean_line + strlen ("return");

  if (STARTWITH (retval_str, "$A"))
    return RETVAL2STR (reg->A);

  int32_t retval = STR2RETVAL (retval_str);
  if (retval == -1)
    error ("%d %s", read_idx, INVALID_RET_VAL);

  retval_str = RETVAL2STR (retval);
  return retval_str;
}

static uint32_t
emu_goto_line (char *clean_line)
{
  char *jmp_to_str = clean_line + strlen ("goto");
  char *end;
  uint32_t jmp_to = strtoul (jmp_to_str, &end, 10);

  if (jmp_to_str == end)
    error ("%d %s", read_idx, INVALID_NR_AFTER_GOTO);

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
      error (INVALID_ALUENUM ": %d\n", alu_enum);
    }
}

static void
emu_alu_neg (reg_mem *reg)
{
  reg->A = -reg->A;
  printf (CYAN_A " = -" CYAN_A "\n");
  return;
}

static void
emu_alu_line (char *clean_line, reg_mem *reg)
{
  char *sym_str = clean_line + strlen ("$A");
  uint8_t sym_enum = parse_alu_sym (sym_str);
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
        error ("%d %s", read_idx, INVALID_RIGHT_VAL);
    }

  emu_do_alu (A_ptr, sym_enum, rval);

  printf (CYAN_A " %.*s " CYAN_S "\n", sym_len, sym_str, rval_str);
}

static void
init_regs (reg_mem *reg)
{
  reg->A = 0;
  reg->X = 0;
  for (int i = 0; i < BPF_MEMWORDS; i++)
    reg->mem[i] = (uint32_t)ARG_INIT_VAL;
}

char *
emu_lines (FILE *read_fp, seccomp_data *data)
{
  line_set Line = { NULL, NULL };
  reg_mem *reg = malloc (sizeof (reg_mem));
  init_regs (reg);

  char *ret = NULL;
  for (read_idx = 1, execute_idx = 1;; read_idx++)
    {
      if (Line.origin_line)
        free_line (&Line);
      pre_asm (read_fp, &Line);
      if (Line.origin_line == NULL)
        break;

      char *clean_line = Line.clean_line;
      char *origin_line = Line.origin_line;

      if (read_idx < execute_idx)
        {
          pre_clear_color (origin_line);
          LIGHTCOLORPRINTF (FORMAT ": %s", read_idx, origin_line);
          continue;
        }
      printf (FORMAT ": ", read_idx);
      execute_idx++;

      if (STARTWITH (clean_line, "if"))
        execute_idx = emu_if_line (clean_line, reg, data);
      else if (STARTWITH (clean_line, "return"))
        {
          ret = emu_ret_line (clean_line, reg);
          break;
        }
      else if (STARTWITH (clean_line, "goto"))
        execute_idx = emu_goto_line (clean_line);
      else if (STARTWITH (clean_line, "$A=-$A"))
        emu_alu_neg (reg);
      else if ((STARTWITH (clean_line, "$") && *(clean_line + 2) == '='))
        emu_assign_line (clean_line, reg, data);
      else if (STARTWITH (clean_line, "$mem["))
        emu_assign_line (clean_line, reg, data);
      else if (STARTWITH (clean_line, "$A"))
        emu_alu_line (clean_line, reg);
      else
        error ("%d %s",read_idx, INVALID_ASM_CODE);
    }

  free_line (&Line);
  free (reg);
  if (ret == NULL)
    error ("%s", MUST_END_WITH_RET);
  return ret;
}

int
global_hide_stdout (int filedup2)
{
  int stdout_backup = dup (STDOUT_FILENO);
  if (stdout_backup == -1)
    error ("dup: %s", strerror (errno));

  if (dup2 (filedup2, STDOUT_FILENO) == -1)
    error ("dup2: %s", strerror (errno));

  return stdout_backup;
}

void
global_ret_stdout (int stdout_backup)
{
  if (dup2 (stdout_backup, STDOUT_FILENO) == -1)
    error ("dup2: %s", strerror (errno));
  close (stdout_backup);
}

void
emulate (ceccomp_args *args)
{
  seccomp_data data = { 0, 0, 0, { 0, 0, 0, 0, 0, 0 } };

  data.arch = args->arch_token;

  if (args->syscall_nr == (char *)ARG_INIT_VAL)
    error ("%s", INPUT_SYS_NR);

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

  printf ("return " CYAN_S "\n", retval_str);
}
