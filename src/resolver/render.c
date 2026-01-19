#include "render.h"
#include "arch_trans.h"
#include "main.h"
#include "parser.h"
#include "resolver.h"
#include "str_pile.h"
#include "token.h"
#include "vector.h"
#include <assert.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static statement_t *local;
static uint32_t default_arch;

typedef enum
{
  NONE = 0b00,
  SYSNR = 0b10,
  ARCH = 0b01,
  MIXED = 0b11,
} stat_t;

typedef struct
{
  uint8_t A_stat;
  uint8_t X_stat;
  uint8_t mem_stat[BPF_MEMWORDS];
  uint32_t arch;
} stat_ctx_t;

static stat_ctx_t *list;

#define FORCE true

static void
set_stat (uint8_t *dest, uint8_t src, bool force)
{
  if (force || *dest == NONE)
    *dest = src;
  else if (*dest != src)
    *dest = MIXED;
  // if *dest != src, we give up tracing.
}

// same as set_stat
static void
set_arch (uint32_t dest_idx, uint32_t src)
{
  if (list[dest_idx].arch == NONE)
    list[dest_idx].arch = src;
  else if (list[dest_idx].arch != src)
    list[dest_idx].arch = MIXED;
}

static void
set_ctx (uint32_t dest_idx, uint32_t src_idx, bool force)
{
  set_stat (&list[dest_idx].A_stat, list[src_idx].A_stat, force);
  set_stat (&list[dest_idx].X_stat, list[src_idx].X_stat, force);
  for (uint32_t i = 0; i < BPF_MEMWORDS; i++)
    set_stat (&list[dest_idx].mem_stat[i], list[src_idx].mem_stat[i], force);
}

static void
assign_line (assign_line_t *assign_line, stat_ctx_t *ctx)
{
  obj_t *left = &assign_line->left_var;
  token_type op = assign_line->operator;
  obj_t *right = &assign_line->right_var;

  uint8_t *left_stat;
  uint8_t right_stat;

  if (left->type == A)
    left_stat = &ctx->A_stat;
  else if (left->type == X)
    left_stat = &ctx->X_stat;
  else if (left->type == MEM)
    left_stat = &ctx->mem_stat[right->data];
  else
    assert (!"Unknown left value type");

  if (op != EQUAL)
    right_stat = MIXED;

  else if (right->type == ATTR_SYSCALL)
    right_stat = SYSNR;
  else if (right->type == ATTR_ARCH)
    right_stat = ARCH;

  else if (right->type == A)
    right_stat = ctx->A_stat;
  else if (right->type == X)
    right_stat = ctx->X_stat;
  else if (right->type == MEM)
    right_stat = ctx->mem_stat[right->data];

  else
    right_stat = MIXED;

  set_stat (left_stat, right_stat, FORCE);
}

static void
ja_line (jump_line_t *jump_line)
{
  uint32_t pc = local->code_nr;
  uint32_t jt = pc + jump_line->jt.code_nr + 1;
  set_ctx (jt, pc, !FORCE);
  set_arch (jt, list[pc].arch);
}

static void
try_resolve_arch (obj_t *cmpobj)
{
  string_t *arch_str = scmp_arch_to_str (cmpobj->data);
  if (arch_str == NULL)
    return;
  cmpobj->type = IDENTIFIER;
  cmpobj->literal = *arch_str;
}

static void
try_resolve_sysnr (obj_t *cmpobj)
{
  uint32_t cur_arch = list[local->code_nr].arch;
  if (cur_arch == NONE)
    return;
  char *sys_name = seccomp_syscall_resolve_num_arch (cur_arch, cmpobj->data);
  if (sys_name == NULL)
    return;

  cmpobj->type = IDENTIFIER;
  string_t *arch_str = NULL;
  if (cur_arch != default_arch)
    arch_str = scmp_arch_to_str (cur_arch);
  cmpobj->literal = persist_object (sys_name, arch_str);
  free (sys_name);
}

static void
jump_line (jump_line_t *jump_line)
{
  if (!jump_line->if_condition)
    return ja_line (jump_line);

  uint32_t pc = local->code_nr;
  uint8_t jt = pc + jump_line->jt.code_nr + 1;
  uint8_t jf = pc + jump_line->jf.code_nr + 1;
  token_type cmp_op = jump_line->comparator;
  uint32_t cmp_data = jump_line->cmpobj.data;
  set_ctx (jt, pc, !FORCE);
  set_ctx (jf, pc, !FORCE);

  // It's hard and unnessary to handle other comparators
  // So just set_arch when comparator is EQUAL_EQUAL
  if (list[pc].A_stat != ARCH)
    {
      set_arch (jt, list[pc].arch);
      set_arch (jf, list[pc].arch);
    }
  else if (cmp_op == EQUAL_EQUAL || cmp_op == BANG_EQUAL)
    {
      set_arch ((cmp_op == EQUAL_EQUAL) ? jt : jf, cmp_data);
      set_arch ((cmp_op == EQUAL_EQUAL) ? jf : jt, MIXED);
    }

  obj_t *cmpobj = &jump_line->cmpobj;
  if (list[pc].A_stat == ARCH)
    try_resolve_arch (cmpobj);

  else if (list[pc].A_stat == SYSNR)
    try_resolve_sysnr (cmpobj);
}

static token_type
ret_data (uint32_t data)
{
  switch (data & 0xffff0000)
    {
    case SCMP_ACT_KILL_PROCESS:
      return KILL_PROC;
    case SCMP_ACT_KILL:
      return KILL;
    case SCMP_ACT_ALLOW:
      return ALLOW;
    case SCMP_ACT_LOG:
      return LOG;
    case SCMP_ACT_TRACE (0):
      return TRACE;
    case _SCMP_ACT_TRAP (0):
      return TRAP;
    case SCMP_ACT_ERRNO (0):
      return ERRNO;
    default:
      return NUMBER;
    }
}

static void
return_line (return_line_t *return_line)
{
  obj_t *ret = &return_line->ret_obj;
  if (ret->type == NUMBER)
    ret->type = ret_data (ret->data);
  if (ret->type != NUMBER) // we need to keep data if "return 0x12345678"
    ret->data &= 0xffff;
}

static void
render_statement (statement_t *statement)
{
  local = statement;

  switch (local->type)
    {
    case ASSIGN_LINE:
      assign_line (&local->assign_line, &list[local->code_nr]);
      set_ctx (local->code_nr + 1, local->code_nr, !FORCE);
      set_arch (local->code_nr + 1, list[local->code_nr].arch);
      break;
    case JUMP_LINE:
      jump_line (&local->jump_line);
      break;
    case RETURN_LINE:
      return_line (&local->return_line);
      break;
    case EMPTY_LINE:
    case EOF_LINE:
    case ERROR_LINE:
      assert (!"type shouldn't be EMPTY, EOF or ERROR");
    default:
      assert (!"Unknown type");
    }
}

void
render (vector_t *v, uint32_t scmp_arch)
{
  default_arch = scmp_arch;

  uint32_t list_len = sizeof (stat_ctx_t) * (v->count + 1);
  // statement code_nr starts from 1
  list = reallocate (NULL, list_len);
  memset (list, NONE, list_len);
  // set default_arch in list[1]
  list[1].arch = scmp_arch;

  for (uint32_t i = 1; i < v->count; i++)
    render_statement (get_vector (v, i));

  reallocate (list, 0);
}
