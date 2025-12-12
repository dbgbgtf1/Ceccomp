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
static bool mem_valid[0x10] = { false };

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
  uint16_t line_len = local->line_end - local->line_start;
  SPRINTF_CAT (print, "%.*s\n", line_len, local->line_start);

  warn ("%s\n", buf);
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
  uint16_t line_len = local->line_end - local->line_start;
  uint16_t err_len = error_line->error_start - local->line_start;
  SPRINTF_CAT (print, "%.*s\n", line_len, local->line_start);
  SPRINTF_CAT (print, "%*s", err_len + 1, "^");

  warn ("%s\n", buf);
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
      if (!mem_valid[right->data])
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
      if (!mem_valid[right->data])
        REPORT_ERROR (UNINITIALIZED_MEM);
    }
}

static void
assign_MEM (assign_line_t *assign_line)
{
  obj_t *left = &assign_line->left_var;
  token_type operator = assign_line->operator;
  obj_t *right = &assign_line->left_var;

  if (operator != EQUAL)
    REPORT_ERROR (OPERATOR_SHOULD_BE_EQUAL);

  if (IS_MEM_OUT_RANGE (left))
    REPORT_ERROR (MEM_IDX_OUT_OF_RANGE);

  if (right->type != A && right->type != X)
    REPORT_ERROR (RIGHT_SHOULD_BE_A_OR_X);

  mem_valid[left->data] = true;
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
jump_line ()
{
  jump_line_t *jump_line = &local->jump_line;
  uint32_t jt = find_key (&jump_line->jt.key);
  uint32_t jf;

  jump_line->jt.type = NUMBER;
  jump_line->jt.code_nr = jt - local->code_nr - 1;
  if ((int32_t)jump_line->jt.code_nr < 0)
    REPORT_ERROR (JT_MUST_BE_POSITIVE);

  if (!jump_line->if_condition)
    return;

  if (jt > UINT8_MAX)
    REPORT_ERROR (JT_TOO_FAR);

  if (jump_line->jf.key.string == NULL)
    {
      jump_line->jf.type = NUMBER;
      jump_line->jf.code_nr = 0;
      return;
    }

  jf = find_key (&jump_line->jf.key);
  jump_line->jf.type = NUMBER;
  jump_line->jf.code_nr = jf - local->code_nr - 1;
  if ((int32_t)jump_line->jt.code_nr < 0)
    REPORT_ERROR (JF_MUST_BE_POSITIVE);

  if (jf > UINT8_MAX)
    REPORT_ERROR (JF_TOO_FAR);
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
    // nothing need to be done for these line
    case RETURN_LINE:
    case EMPTY_LINE:
    case EOF_LINE:
      return;
    }
}

bool
resolver (vector_t *v)
{
  has_error = false;

  for (uint32_t idx = 0; idx < v->count; idx++)
    resolve_statement (get_vector (v, idx));

  statement_t *last = get_vector(v, v->count - 1);
  if (last->type != RETURN_LINE)
    report_error (EXPECT_RETURN_IN_THE_END);

  if (has_error)
    return true;
  return false;
}
