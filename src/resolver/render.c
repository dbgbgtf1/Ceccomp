#include "render.h"
#include "arch_trans.h"
#include "parser.h"
#include "resolver.h"
#include "token.h"
#include "vector.h"
#include <assert.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static statement_t *local;
static uint32_t default_arch;
static vector_t *ptr_list;

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
set_arch (uint32_t *dest, uint32_t src)
{
  if (*dest == NONE)
    *dest = src;
  else if (*dest != src)
    *dest = MIXED;
}

static void
set_ctx (stat_ctx_t *dest, stat_ctx_t *src, bool force)
{
  set_stat (&dest->A_stat, src->A_stat, force);
  set_stat (&dest->X_stat, src->X_stat, force);
  for (uint32_t i = 0; i < BPF_MEMWORDS; i++)
    set_stat (&dest->mem_stat[i], src->mem_stat[i], force);
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
    assert (0);

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
ja_line (jump_line_t *jump_line, stat_ctx_t *stat_list)
{
  uint32_t jt = jump_line->jt.code_nr;
  set_ctx (&stat_list[jt], &stat_list[local->code_nr], !FORCE);
  set_arch (&stat_list[jt].arch, stat_list[local->code_nr].arch);
}

static void
try_resolve_arch (obj_t *cmpobj)
{
  char *arch_str = scmp_arch_to_str (cmpobj->data);
  if (arch_str == NULL)
    return;
  cmpobj->literal.start = arch_str;
  cmpobj->literal.len = strlen (arch_str);
  cmpobj->type = ATTR_ARCH;
}

static void
try_resolve_sysnr (stat_ctx_t *stat_list, obj_t *cmpobj)
{
  uint32_t cur_arch = stat_list[local->code_nr].arch;
  char *sys_name = seccomp_syscall_resolve_num_arch (cur_arch, cmpobj->data);
  if (sys_name == NULL)
    return;

  cmpobj->type = ATTR_SYSCALL;
  if (cur_arch == default_arch)
    {
      cmpobj->literal.start = sys_name;
      cmpobj->literal.len = strlen (sys_name);
      push_vector (ptr_list, &sys_name);
    }
  else
    {
      char *buf = malloc (0x30);
      cmpobj->literal.len = snprintf (buf, 0x30, "%s.%s",
                                      scmp_arch_to_str (cur_arch), sys_name);
      push_vector (ptr_list, &buf);
    }
}

static void
jump_line (jump_line_t *jump_line, stat_ctx_t *stat_list)
{
  if (!jump_line->if_condition)
    return ja_line (jump_line, stat_list);

  uint8_t jt = jump_line->jt.code_nr;
  uint8_t jf = jump_line->jf.code_nr;
  set_ctx (&stat_list[jt], &stat_list[local->code_nr], !FORCE);
  set_ctx (&stat_list[jf], &stat_list[local->code_nr], !FORCE);

  // It's hard and unnessary to handle other comparators
  // So just set_arch when comparator is EQUAL
  if (stat_list[local->code_nr].A_stat != ARCH)
    {
      set_arch (&stat_list[jt].arch, stat_list[local->code_nr].arch);
      set_arch (&stat_list[jf].arch, stat_list[local->code_nr].arch);
    }
  else if (jump_line->cond.comparator == EQUAL)
    {
      set_arch (&stat_list[jt].arch, jump_line->cond.cmpobj.data);
      set_arch (&stat_list[jf].arch, MIXED);
    }

  obj_t *cmpobj = &jump_line->cond.cmpobj;
  if (stat_list[local->code_nr].A_stat == ARCH)
    try_resolve_arch (cmpobj);

  else if (stat_list[local->code_nr].A_stat == SYSNR)
    try_resolve_sysnr (stat_list, cmpobj);
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
      assert (0);
    }
}

static void
return_line (return_line_t *return_line)
{
  obj_t *ret = &return_line->ret_obj;
  if (ret->type == NUMBER)
    ret->type = ret_data (ret->data);
  ret->data &= 0xffff;

  ret->literal.start = token_pairs[ret->type];
  ret->literal.len = strlen (token_pairs[ret->type]);
}

static void
render_statement (statement_t *statement, stat_ctx_t *stat_list)
{
  local = statement;

  switch (local->type)
    {
    case ASSIGN_LINE:
      assign_line (&local->assign_line, &stat_list[local->code_nr]);
      break;
    case JUMP_LINE:
      jump_line (&local->jump_line, stat_list);
      break;
    case RETURN_LINE:
      return_line (&local->return_line);
      break;
    case EMPTY_LINE:
    case EOF_LINE:
    case ERROR_LINE:
      assert (0);
    }
}

void
render (vector_t *v, vector_t *v_ptr, uint32_t scmp_arch)
{
  default_arch = scmp_arch;
  ptr_list = v_ptr;

  uint32_t stat_list_len = sizeof (stat_ctx_t) * (v->count - 1);
  stat_ctx_t *stat_list = reallocate (NULL, stat_list_len);
  memset (stat_list, NONE, stat_list_len);

  for (uint32_t i = 0; i < v->count - 1; i++)
    render_statement (get_vector (v, i), stat_list);

  reallocate (stat_list, 0);
}
