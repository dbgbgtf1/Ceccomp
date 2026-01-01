#include "emu.h"
#include "color.h"
#include "log/error.h"
#include "log/logger.h"
#include "parse_args.h"
#include "parser.h"
#include "formatter.h"
#include "read_source.h"
#include "resolver.h"
#include "scanner.h"
#include "token.h"
#include "vector.h"
#include <assert.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t A_reg = 0;
static uint32_t X_reg = 0;
static uint32_t mem[BPF_MEMWORDS] = { 0 };

static uint32_t syscall_nr = 0;
static uint32_t scmp_arch = 0;
static uint32_t low_pc = 0;
static uint32_t high_pc = 0;
static uint32_t low_args[6] = { 0 };
static uint32_t high_args[6] = { 0 };

static uint32_t *vars[] = {
  [ATTR_SYSCALL] = &syscall_nr,
  [ATTR_ARCH] = &scmp_arch,
  [ATTR_LOWPC] = &low_pc,
  [ATTR_HIGHPC] = &high_pc,
  [ATTR_LOWARG] = low_args,
  [ATTR_HIGHARG] = high_args,
  [A] = &A_reg,
  [X] = &X_reg,
  [MEM] = mem,
};

#define DO_OPERATE(operator) (*left operator (*right))

static void
assign_line (assign_line_t *assign_line)
{
  uint32_t *left = vars[assign_line->left_var.type];

  token_type right_type = assign_line->right_var.type;
  uint32_t *right = vars[right_type];
  if (right_type == ATTR_LOWARG || right_type == ATTR_HIGHARG)
    right += assign_line->right_var.data;
  if (right_type == NUMBER)
    right = &assign_line->right_var.data;

  switch (assign_line->operator)
    {
    case ADD_TO:
      DO_OPERATE (+=);
      break;
    case SUB_TO:
      DO_OPERATE (-=);
      break;
    case MULTI_TO:
      DO_OPERATE (*=);
      break;
    case DIVIDE_TO:
      DO_OPERATE (/=);
      break;
    case LSH_TO:
      DO_OPERATE (<<=);
      break;
    case RSH_TO:
      DO_OPERATE (>>=);
      break;
    case AND_TO:
      DO_OPERATE (&=);
      break;
    case OR_TO:
      DO_OPERATE (|=);
      break;
    case XOR_TO:
      DO_OPERATE (^=);
      break;
    case EQUAL:
      DO_OPERATE (=);
      break;
    case NEGATIVE:
      DO_OPERATE (= -);
      break;
    default:
      assert (0);
    }
}

#define DO_COMPARE(comparator) (bool)(A_reg comparator right)

static uint32_t
jump_line (jump_line_t *jump_line)
{
  uint32_t jt = jump_line->jt.code_nr;
  uint32_t jf = jump_line->jf.code_nr;

  if (!jump_line->if_condition)
    return jt;

  bool cond_true = false;
  if (jump_line->if_bang)
    cond_true = true;

  uint32_t right = 0;
  if (jump_line->cond.cmpobj.type == X)
    right = X_reg;
  else
    right = jump_line->cond.cmpobj.data;

  switch (jump_line->cond.comparator)
    {
    case EQUAL_EQUAL:
      cond_true ^= DO_COMPARE (==);
      break;
    case BANG_EQUAL:
      cond_true ^= DO_COMPARE (!=);
      break;
    case GREATER_EQUAL:
      cond_true ^= DO_COMPARE (>=);
      break;
    case GREATER_THAN:
      cond_true ^= DO_COMPARE (>);
      break;
    case LESS_EQUAL:
      cond_true ^= DO_COMPARE (<=);
      break;
    case LESS_THAN:
      cond_true ^= DO_COMPARE (<);
      break;
    case AND:
      cond_true ^= DO_COMPARE (&);
      break;
    default:
      assert (0);
    }

  return (cond_true ? jt : jf);
}

static char ret_char[0x100] = "";

static char *
paren_num (token_type ret, uint32_t paren_num)
{
  snprintf (ret_char, 0x100, "%s(%d)", token_pairs[ret], paren_num);
  return ret_char;
}

static char *
return_line (return_line_t *return_line)
{
  uint32_t ret_data;
  if (return_line->ret_obj.type == A)
    ret_data = A_reg;
  else
    ret_data = return_line->ret_obj.data;

  switch (ret_data & 0xffff0000)
    {
    case SCMP_ACT_KILL_PROCESS:
      return token_pairs[KILL_PROC];
    case SCMP_ACT_KILL:
      return token_pairs[KILL];
    case SCMP_ACT_ALLOW:
      return token_pairs[ALLOW];
    case SCMP_ACT_LOG:
      return token_pairs[LOG];
    case SCMP_ACT_TRACE (0):
      return paren_num (TRACE, ret_data & 0xffff);
    case _SCMP_ACT_TRAP (0):
      return paren_num (TRAP, ret_data & 0xffff);
    case SCMP_ACT_ERRNO (0):
      return paren_num (ERRNO, ret_data & 0xffff);
    default:
      assert (0);
    }
}

static char *
emu_statements (vector_t *v)
{
  uint32_t read_idx = 0;
  uint32_t exec_idx = 0;

  for (; read_idx < v->count - 1; read_idx++)
    {
      statement_t *statement = get_vector (v, read_idx);
      uint32_t len = statement->line_end - statement->line_start;

      if (read_idx < exec_idx)
        {
          printf (LIGHT ("%*s\n"), len, statement->line_start);
          continue;
        }

      printf ("%*s\n", len, statement->line_start);
      exec_idx++;

      switch (statement->type)
        {
        case ASSIGN_LINE:
          assign_line (&statement->assign_line);
          break;
        case JUMP_LINE:
          exec_idx += jump_line (&statement->jump_line);
          break;
        case RETURN_LINE:
          return return_line (&statement->return_line);
        case EMPTY_LINE:
          break;
        default:
          assert (0);
        }
    }

  assert (0);
}

static void
init_attr (emu_arg_t *emu_arg)
{
  if (emu_arg->sys_name == NULL)
    error ("%s", INPUT_SYS_NR);
  syscall_nr = seccomp_syscall_resolve_name_arch (emu_arg->arch_enum,
                                                  emu_arg->sys_name);
  if ((int32_t)syscall_nr == __NR_SCMP_ERROR)
    error ("%s", INVALID_SYSNR);

  scmp_arch = emu_arg->arch_enum;
  low_pc = emu_arg->ip & UINT32_MAX;
  high_pc = emu_arg->ip >> 32;
  for (uint32_t i = 0; i < 6; i++)
    {
      low_args[i] = emu_arg->args[i] & UINT32_MAX;
      high_args[i] = emu_arg->args[i] >> 32;
    }
}

void
emulate (emu_arg_t *emu_arg)
{
  init_attr (emu_arg);

  init_source (emu_arg->text_file);
  init_scanner (next_line ());
  init_parser (emu_arg->arch_enum);
  init_table ();

  vector_t v;
  init_vector (&v, sizeof (statement_t));
  statement_t statement;
  do
    {
      parse_line (&statement);
      push_vector (&v, &statement);
    }
  while (statement.type != EOF_LINE);

  if (resolver (&v))
    error ("%s", EMU_TERMINATED);
  // if ERROR_LINE exists, then exits

  char *ret = emu_statements (&v);
  printf ("%s", ret);

  free_table ();
  free_source ();
  free_vector (&v);
}
