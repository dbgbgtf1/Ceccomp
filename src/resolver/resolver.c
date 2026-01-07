#include "resolver.h"
#include "hash.h"
#include "log/error.h"
#include "log/logger.h"
#include "parser.h"
#include "token.h"
#include "vector.h"
#include <assert.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

bool has_error;
static statement_t *local;
static uint16_t *masks, mem_valid = 0;
static uint16_t bpf_len = 0;

#define REPORT_ERROR(error_msg)                                               \
  do                                                                          \
    {                                                                         \
      report_error (error_msg);                                               \
      return;                                                                 \
    }                                                                         \
  while (0)

#define SPRINTF_CAT(...) print += sprintf (__VA_ARGS__)

static void
report_error (char *error_msg)
{
  has_error = true;
  char buf[0x400];
  char *print = buf;

  SPRINTF_CAT (print, "At %04d: ", local->text_nr);
  SPRINTF_CAT (print, "%s\n", error_msg);
  SPRINTF_CAT (print, "%.*s", local->line_len, local->line_start);

  warn ("%s", buf);
}

static bool
match_from_to (token_type type, token_type from, token_type to)
{
  if (type < from || type > to)
    return false;

  return true;
}

static void
error_line ()
{
  has_error = true;
  char buf[0x400];
  char *print = buf;

  error_line_t *error_line = &local->error_line;

  SPRINTF_CAT (print, "At %04d: ", local->text_nr);
  SPRINTF_CAT (print, "%s\n", error_line->error_msg);
  uint16_t err_len = error_line->error_start - local->line_start;
  SPRINTF_CAT (print, "%.*s\n", local->line_len, local->line_start);
  SPRINTF_CAT (print, "%*s", err_len + 1, "^");

  warn ("%s", buf);
}
#undef SPRINTF_CAT

#define IS_ARG_OUT_RANGE(obj) is_out_range (obj, 0x5)
#define IS_MEM_OUT_RANGE(obj) is_out_range (obj, 0x15)

static bool
is_out_range (obj_t *obj, uint32_t max_idx)
{
  if (obj->data > max_idx)
    return true;
  return false;
}

static void
assign_A (assign_line_t *assign_line)
{
  token_type operator = assign_line->operator;
  obj_t *right = &assign_line->right_var;

  if (operator == NEGATIVE)
    {
      if (right->type != A)
        REPORT_ERROR (RIGHT_SHOULD_BE_A);
      return;
    }
  else if (match_from_to (operator, ADD_TO, XOR_TO))
    {
      if (right->type != X && right->type != NUMBER)
        REPORT_ERROR (RIGHT_SHOULD_BE_X_OR_NUM);

      if (operator == DIVIDE_TO && right->type == NUMBER && right->data == 0)
        REPORT_ERROR (ALU_DIV_BY_ZERO);

      if (match_from_to (operator, LSH_TO, RSH_TO))
        if (right->type == NUMBER && right->data >= 32)
          REPORT_ERROR (ALU_SH_OUT_OF_RANGE);
      return;
    }

  assert (operator == EQUAL);

  if (right->type == ATTR_LEN)
    {
      right->type = NUMBER;
      right->data = LEN_VAL;
    }
  else if (right->type == A)
    REPORT_ERROR (RIGHT_CAN_NOT_BE_A);
  else if ((right->type == ATTR_LOWARG || right->type == ATTR_HIGHARG)
           && IS_ARG_OUT_RANGE (right))
    REPORT_ERROR (ARGS_IDX_OUT_OF_RANGE);
  else if (right->type == MEM)
    {
      if (IS_MEM_OUT_RANGE (right))
        REPORT_ERROR (MEM_IDX_OUT_OF_RANGE);
      if (!(mem_valid & (1 << right->data)))
        REPORT_ERROR (UNINITIALIZED_MEM);
    }
}

static void
assign_X (assign_line_t *assign_line)
{
  token_type *operator = &assign_line->operator;
  obj_t *right = &assign_line->right_var;

  if (*operator != EQUAL)
    REPORT_ERROR (OPERATOR_SHOULD_BE_EQUAL);

  if (right->type == ATTR_LEN)
    {
      right->type = NUMBER;
      right->data = LEN_VAL;
    }
  else if (match_from_to (right->type, ATTR_SYSCALL, ATTR_HIGHARG))
    REPORT_ERROR (LEFT_SHOULD_BE_A);

  else if (right->type == X)
    REPORT_ERROR (RIGHT_CAN_NOT_BE_X);
  else if ((right->type == ATTR_LOWARG || right->type == ATTR_HIGHARG)
           && IS_ARG_OUT_RANGE (right))
    REPORT_ERROR (ARGS_IDX_OUT_OF_RANGE);
  else if (right->type == MEM)
    {
      if (IS_MEM_OUT_RANGE (right))
        REPORT_ERROR (MEM_IDX_OUT_OF_RANGE);
      if (!(mem_valid & (1 << right->data)))
        REPORT_ERROR (UNINITIALIZED_MEM);
    }
}

static void
assign_MEM (assign_line_t *assign_line)
{
  obj_t *left = &assign_line->left_var;
  token_type operator = assign_line->operator;
  obj_t *right = &assign_line->right_var;

  if (operator != EQUAL)
    REPORT_ERROR (OPERATOR_SHOULD_BE_EQUAL);

  if (IS_MEM_OUT_RANGE (left))
    REPORT_ERROR (MEM_IDX_OUT_OF_RANGE);

  if (right->type != A && right->type != X)
    REPORT_ERROR (RIGHT_SHOULD_BE_A_OR_X);

  mem_valid |= (1 << left->data);
}

static void
assign_line ()
{
  assign_line_t *assign_line = &local->assign_line;
  if (assign_line->left_var.type == A)
    assign_A (assign_line);
  else if (assign_line->left_var.type == X)
    assign_X (assign_line);
  else if (assign_line->left_var.type == MEM)
    assign_MEM (assign_line);
}

static void
set_jt_jf (label_t *label, uint32_t code_nr)
{
  label->type = NUMBER;
  label->code_nr = code_nr - local->code_nr - 1;
}

static void
ja_line (jump_line_t *jump_line)
{
  uint32_t jt = find_key (&jump_line->jt.key);
  set_jt_jf (&jump_line->jt, jt);

  masks[jt] &= mem_valid;
  mem_valid = ~0;
}

static void
jump_line ()
{
  jump_line_t *jump_line = &local->jump_line;

  if (!jump_line->if_condition)
    return ja_line (jump_line);

  uint32_t jt = find_key (&jump_line->jt.key);
  set_jt_jf (&jump_line->jt, jt);

  if ((int16_t)jump_line->jt.code_nr < 0)
    REPORT_ERROR (JT_MUST_BE_POSITIVE);
  if (jump_line->jt.code_nr > UINT8_MAX)
    REPORT_ERROR (JT_TOO_FAR);
  if (jt > bpf_len)
    REPORT_ERROR (JT_INVALID_TAG);

  if (jump_line->jf.key.start == NULL)
    set_jt_jf (&jump_line->jf, local->code_nr + 1);
  else
    set_jt_jf (&jump_line->jf, find_key (&jump_line->jf.key));

  uint32_t jf = local->code_nr + jump_line->jf.code_nr + 1;
  if ((int16_t)jump_line->jf.code_nr < 0)
    REPORT_ERROR (JF_MUST_BE_POSITIVE);
  if (jump_line->jf.code_nr > UINT8_MAX)
    REPORT_ERROR (JF_TOO_FAR);
  if (jf > bpf_len)
    REPORT_ERROR (JF_INVALID_TAG);

  masks[jt] &= mem_valid;
  masks[jf] &= mem_valid;
  mem_valid = ~0;
}

static void
return_line ()
{
  return_line_t *return_line = &local->return_line;
  token_type ret_type = return_line->ret_obj.type;
  if (ret_type == A || ret_type == NUMBER)
    return;

  if ((ret_type == TRACE || ret_type == TRAP || ret_type == ERRNO)
      && return_line->ret_obj.data > 0xffff)
    REPORT_ERROR (RET_DATA_OVERFLOW);
  // Don't assume the ret_obj.data == zero when not used
}

static void
resolve_statement (statement_t *statement)
{
  local = statement;

  switch (local->type)
    {
    case ERROR_LINE:
      error_line ();
      return;
    case ASSIGN_LINE:
      assign_line ();
      return;
    case JUMP_LINE:
      jump_line ();
      return;
    case RETURN_LINE:
      return_line ();
      return;
    // nothing need to be done for these line
    case EMPTY_LINE:
    case EOF_LINE:
      assert (0);
    }
}

bool
resolver (vector_t *code_ptr_v)
{
  has_error = false;

  masks = reallocate (NULL, sizeof (*masks) * (code_ptr_v->count));
  memset (masks, 0xff, sizeof (*masks) * (code_ptr_v->count));
  mem_valid = 0;

  bpf_len = code_ptr_v->count - 1;

  for (uint32_t i = 1; i < code_ptr_v->count; i++)
    {
      mem_valid &= masks[i];
      statement_t **ptr = get_vector (code_ptr_v, i);
      resolve_statement (*ptr);
    }

  statement_t **last = get_vector (code_ptr_v, code_ptr_v->count - 1);
  if ((*last)->type != RETURN_LINE)
    report_error (MUST_END_WITH_RET);

  reallocate (masks, 0x0);

  if (has_error)
    return true;
  return false;
}
