#include "decode_filters.h"
#include "check_prog.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include "parser.h"
#include "token.h"
#include "vector.h"
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static token_type abs_table[] = {
  [offsetof (seccomp_data, nr)] = ATTR_SYSCALL,
  [offsetof (seccomp_data, arch)] = ATTR_ARCH,
  [offsetof (seccomp_data, instruction_pointer)] = ATTR_LOWPC,
  [offsetof (seccomp_data, instruction_pointer) + 4] = ATTR_HIGHPC,
  [offsetof (seccomp_data, args[0])] = ATTR_LOWARG,
  [offsetof (seccomp_data, args[0]) + 4] = ATTR_HIGHARG,
  [offsetof (seccomp_data, args[1])] = ATTR_LOWARG,
  [offsetof (seccomp_data, args[1]) + 4] = ATTR_HIGHARG,
  [offsetof (seccomp_data, args[2])] = ATTR_LOWARG,
  [offsetof (seccomp_data, args[2]) + 4] = ATTR_HIGHARG,
  [offsetof (seccomp_data, args[3])] = ATTR_LOWARG,
  [offsetof (seccomp_data, args[3]) + 4] = ATTR_HIGHARG,
  [offsetof (seccomp_data, args[4])] = ATTR_LOWARG,
  [offsetof (seccomp_data, args[4]) + 4] = ATTR_HIGHARG,
  [offsetof (seccomp_data, args[5])] = ATTR_LOWARG,
  [offsetof (seccomp_data, args[5]) + 4] = ATTR_HIGHARG,
};

static void
ld_ldx_line (filter f, statement_t *statement)
{
  statement->type = ASSIGN_LINE;
  assign_line_t *assign_line = &statement->assign_line;

  assign_line->left_var.type = (BPF_CLASS (f.code) == BPF_LD) ? A : X;
  assign_line->operator = EQUAL;

  obj_t *right = &assign_line->right_var;
  switch (BPF_MODE (f.code))
    {
    case BPF_IMM:
      right->type = NUMBER;
      right->data = f.k;
      return;
    case BPF_MEM:
      right->type = MEM;
      right->data = f.k;
      return;
    case BPF_ABS:
      right->type = abs_table[f.k];
      if (right->type == ATTR_LOWARG || right->type == ATTR_HIGHARG)
        right->data = (f.k - offsetof (seccomp_data, args[0])) / 0x8;
      return;
    }
}

static void
st_stx_line (filter f, statement_t *statement)
{
  statement->type = ASSIGN_LINE;
  assign_line_t *assign_line = &statement->assign_line;

  assign_line->left_var.type = MEM;
  assign_line->left_var.data = f.k;
  assign_line->operator = EQUAL;

  assign_line->right_var.type = (BPF_CLASS (f.code) == BPF_ST) ? A : X;
}

static token_type operator_table[] = {
  [BPF_ADD] = ADD_TO,    [BPF_SUB] = SUB_TO, [BPF_MUL] = MULTI_TO,
  [BPF_DIV] = DIVIDE_TO, [BPF_OR] = OR_TO,   [BPF_AND] = AND_TO,
  [BPF_LSH] = LSH_TO,    [BPF_RSH] = RSH_TO, [BPF_NEG] = NEGATIVE,
  [BPF_XOR] = XOR_TO,
};

static void
alu_line (filter f, statement_t *statement)
{
  statement->type = ASSIGN_LINE;
  assign_line_t *assign_line = &statement->assign_line;

  assign_line->left_var.type = A;

  if (BPF_SRC (f.code) == BPF_X)
    assign_line->right_var.type = X;
  else
    {
      assign_line->right_var.type = NUMBER;
      assign_line->right_var.data = f.k;
    }

  assign_line->operator = operator_table[BPF_OP (f.code)];
}

static void
ja_line (filter f, jump_line_t *statement)
{
  statement->if_bang = false;
  statement->if_condition = false;
  statement->jt.type = NUMBER;
  statement->jt.code_nr = f.k;
}

static token_type comparator_table[] = {
  [BPF_JEQ] = EQUAL_EQUAL,
  [BPF_JGT] = GREATER_THAN,
  [BPF_JGE] = GREATER_EQUAL,
  [BPF_JSET] = AND,
};

static token_type reverse_table[] = {
  [BPF_JEQ] = BANG_EQUAL,
  [BPF_JGT] = LESS_EQUAL,
  [BPF_JGE] = LESS_THAN,
};

static void
condition (filter f, jump_condition_t *cond, bool *if_bang)
{
  uint32_t op = BPF_OP (f.code);
  if ((!*if_bang) || op == BPF_JSET)
    cond->comparator = comparator_table[op];
  else
    {
      cond->comparator = reverse_table[op];
      *if_bang = false;
    }

  if (BPF_SRC (f.code) == BPF_X)
    cond->cmpobj.type = X;
  else
    {
      cond->cmpobj.type = NUMBER;
      cond->cmpobj.data = f.k;
    }
}

static void
jump_line (filter f, statement_t *statement)
{
  statement->type = JUMP_LINE;
  jump_line_t *jump_line = &statement->jump_line;

  if (BPF_OP (f.code) == BPF_JA)
    return ja_line (f, jump_line);

  jump_line->if_condition = true;
  jump_line->jt.type = NUMBER;
  jump_line->jf.type = NUMBER;

  if (f.jt == 0 && f.jf != 0)
    {
      jump_line->if_bang = true;
      jump_line->jf.code_nr = f.jt;
      jump_line->jt.code_nr = f.jf;
    }
  else
    {
      jump_line->jt.code_nr = f.jt;
      jump_line->jf.code_nr = f.jf;
    }

  condition (f, &jump_line->cond, &jump_line->if_bang);
}

static void
return_line (filter f, statement_t *statement)
{
  statement->type = RETURN_LINE;
  return_line_t *return_line = &statement->return_line;

  if (BPF_RVAL (BPF_A) == BPF_X)
    return_line->ret_obj.type = X;
  else
    {
      return_line->ret_obj.type = NUMBER;
      return_line->ret_obj.data = f.k;
    }
}

static void
misc_line (filter f, statement_t *statement)
{
  statement->type = ASSIGN_LINE;
  assign_line_t *assign_line = &statement->assign_line;
  assign_line->operator = EQUAL;

  if (BPF_MISCOP (f.code) == BPF_TAX)
    {
      assign_line->left_var.type = X;
      assign_line->right_var.type = A;
    }
  else
    {
      assign_line->left_var.type = A;
      assign_line->right_var.type = X;
    }
}

static void
decode_filter (filter f, statement_t *statement)
{
  switch (BPF_CLASS (f.code))
    {
    case BPF_LD:
    case BPF_LDX:
      ld_ldx_line (f, statement);
      return;
    case BPF_ST:
    case BPF_STX:
      st_stx_line (f, statement);
      return;
    case BPF_ALU:
      alu_line (f, statement);
      break;
    case BPF_JMP:
      jump_line (f, statement);
      break;
    case BPF_RET:
      return_line (f, statement);
      break;
    case BPF_MISC:
      misc_line (f, statement);
      break;
    }
}

void
decode_filters (fprog *prog, vector_t *v)
{
  if (check_prog (prog))
    error ("%s", DISASM_TERMINATED);

  statement_t statement;

  for (uint32_t i = 0; i < prog->len; i++)
    {
      memset (&statement, '\0', sizeof (statement_t));

      statement.text_nr = i + 1;
      statement.code_nr = i + 1;

      decode_filter (prog->filter[i], &statement);
      push_vector (v, &statement);
    }
}
