#include "parser.h"
#include "hash.h"
#include "log/error.h"
#include "scanner.h"
#include "token.h"
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct
{
  uint16_t line_nr;
  char *line_start;

  token_t previous;
  token_t current;
  token_t next;
} parser_t;

parser_t parser = { .line_nr = 0 };
state_ment_t *local;
jmp_buf g_env;

static void
advance ()
{
  parser.previous = parser.current;
  parser.current = parser.next;
  parser.next = scan_token ();
}

static bool
peek (token_type expected)
{
  if (expected != parser.next.type)
    return false;

  return true;
}

static bool
peek_from_to (token_type expected_start, token_type expected_end)
{
  if (parser.next.type < expected_start || parser.next.type > expected_end)
    return false;

  return true;
}

static bool
match (token_type expected)
{
  if (!peek (expected))
    return false;

  advance ();
  return true;
}

static bool
match_from_to (token_type expected_start, token_type expected_end)
{
  if (!peek_from_to (expected_start, expected_end))
    return false;

  advance ();
  return true;
}

static void
error_at (token_t token, char *err_msg)
{
  local->type = ERROR_LINE;
  local->error_line.error_token = token;
  local->error_line.offset = token.token_start - parser.line_start;
  local->error_line.error_msg = err_msg;

  while (!(match (NEWLINE) || peek (TOKEN_EOF)))
    advance ();
  longjmp (g_env, 1);
}

// paren_num can be ignored, default as 0
static uint32_t
paren_num ()
{
  if (!match (LEFT_PAREN))
    return 0;
  if (!match (NUMBER))
    error_at (parser.next, EXPECT_NUMBER);
  if (!match (RIGHT_PAREN))
    error_at (parser.next, EXPECT_PAREN);
  return parser.previous.data;
}

// but bracket_num can not be ignored
static uint32_t
bracket_num ()
{
  if (!match (LEFT_BRACKET))
    error_at (parser.next, EXPECT_BRACKET);
  if (!match (NUMBER))
    error_at (parser.next, EXPECT_NUMBER);
  if (!match (RIGHT_BRACKET))
    error_at (parser.next, EXPECT_BRACKET);
  return parser.previous.data;
}

static void
empty_line ()
{
  local->type = EMPTY_LINE;
  return;
}

static void
eof_line ()
{
  local->type = EOF_LINE;
  return;
}

static void
ret_obj ()
{
  obj_t *obj = &local->return_line.ret_obj;
  obj->type = parser.current.type;

  if (match_from_to (TRACE, ERRNO))
    {
      obj->type = parser.current.type;
      obj->data = paren_num ();
    }
  else if (match_from_to (KILL_PROC, LOG) || match (A))
    obj->type = parser.current.type;
  else
    error_at (parser.next, EXPECT_RETURN_VAL);
}

static void
return_line ()
{
  local->type = RETURN_LINE;

  ret_obj ();
}

static void
label (label_t *label)
{
  if (!match (IDENTIFIER))
    error_at (parser.next, EXPECT_LABEL);
  label->string = parser.current.token_start;
  label->len = parser.current.token_len;
}

static void
compare_obj (obj_t *obj)
{
  if (match (X))
    obj->type = parser.current.type;
  else if (match (NUMBER))
    {
      obj->type = parser.current.type;
      obj->data = parser.current.data;
    }
  else if (match_from_to (ARCH_X86, ARCH_RISCV64))
    {
      // i386
      if (!match (DOT))
        obj->type = parser.current.type;
      // i386.read
      else
        {
          if (!peek (IDENTIFIER))
            error_at (parser.next, EXPECT_SYSCALL);
          obj->type = ATTR_SYSCALL;
          obj->string.string = parser.previous.token_start;
          obj->string.len = parser.previous.token_len
                            + parser.current.token_len + parser.next.token_len;
          advance ();
        }
    }
  else if (match (IDENTIFIER))
    {
      obj->type = ATTR_SYSCALL;
      obj->string.string = parser.current.token_start;
      obj->string.len = parser.current.token_len;
    }
  // read
}

static void
condition (jump_line_t *jump_line)
{
  jump_line->if_condition = true;

  if (match (BANG))
    jump_line->if_bang = true;

  if (!match (LEFT_PAREN))
    error_at (parser.next, EXPECT_PAREN);
  if (!match (A))
    error_at (parser.next, EXPECT_A);
  if (!match_from_to (EQUAL_EQUAL, LESS_THAN))
    error_at (parser.next, EXPECT_COMPARTOR);
  jump_line->cond.comparator = parser.current.type;

  compare_obj (&jump_line->cond.cmpobj);

  if (!match (RIGHT_PAREN))
    error_at (parser.next, EXPECT_PAREN);
}

static void
jump_line ()
{
  local->type = JUMP_LINE;
  jump_line_t *jump_line = &local->jump_line;

  if (parser.current.type == IF)
    condition (jump_line);

  if (!match (GOTO))
    error_at (parser.next, EXPECT_GOTO);

  label (&jump_line->jt);
  jump_line->jf.string = NULL;
  // jf default as zero

  if (peek (NEWLINE) || peek (TOKEN_EOF))
    return;

  if (!match (COMMA))
    error_at (parser.next, EXPECT_COMMA);
  if (!match (ELSE))
    error_at (parser.next, EXPECT_ELSE);
  if (!match (GOTO))
    error_at (parser.next, EXPECT_GOTO);

  label (&jump_line->jf);
}

static void
left (assign_line_t *assign_line)
{
  assign_line->left_var.type = parser.current.type;
  // expression checked for us, it must be A X MEM here

  if (parser.current.type == MEM)
    assign_line->left_var.data = bracket_num ();
}

static void
right (assign_line_t *assign_line)
{
  if (match (A) || match (X) || match_from_to (ATTR_SYSCALL, ATTR_HIGHPC))
    assign_line->right_var.type = parser.current.type;
  else if (match (MEM) || match (ATTR_LOWARG) || match (ATTR_HIGHARG))
    {
      assign_line->right_var.type = parser.current.type;
      assign_line->right_var.data = bracket_num ();
    }
  else if (match (ATTR_LEN))
    {
      assign_line->right_var.type = NUMBER;
      assign_line->right_var.data = LEN_VAL;
    }
  else if (match (NUMBER))
    {
      assign_line->right_var.type = parser.current.type;
      assign_line->right_var.data = parser.current.data;
    }
  else
    error_at (parser.next, EXPECT_RIGHT_VAR);
}

static void
assign_line ()
{
  local->type = ASSIGN_LINE;
  assign_line_t *assign_line = &local->assign_line;

  left (assign_line);

  if (match_from_to (ADD_TO, XOR_TO))
    assign_line->operator = parser.current.type;
  else if (match (EQUAL))
    {
      // if we match NEGATIVE, use NEGATIVE to overwrite operator
      // else use EQUAL as operator
      match (NEGATIVE);
      assign_line->operator = parser.current.type;
    }
  else
    error_at (parser.next, EXPECT_OPERATOR);

  right (assign_line);
}

static void
expression ()
{
  if (match (NEWLINE))
    return empty_line ();
  if (match (TOKEN_EOF))
    return eof_line ();

  if (match (RETURN))
    return_line ();
  else if (match (IF) || peek (GOTO))
    jump_line ();
  else if (match_from_to (A, MEM))
    assign_line ();
  else
    error_at (parser.next, UNEXPECT_TOKEN);

  if (match (NEWLINE) || peek (TOKEN_EOF))
    return;
  error_at (parser.next, UNEXPECT_TOKEN);
}

static void
label_decl ()
{
  if (!match (LABEL_DECL))
    return;

  label_t label = { .string = parser.current.token_start,
                    .len = parser.current.token_len };
  insert_key (label, parser.line_nr);

  // ignore our disasm useless output
  uint32_t count = 0;
  while (match (NUMBER) && count < 4)
    count++;
}

void
init_parser ()
{
  advance ();
}

void
parse_line (state_ment_t *state_ment)
{
  // ignore our disasm useless output
  while (match_from_to (USELESS0, USELESS1))
    match (NEWLINE);

  local = state_ment;
  memset (local, '\0', sizeof (state_ment_t));

  parser.line_nr++;
  parser.line_start = parser.next.token_start;
  state_ment->line_nr = parser.line_nr;

  if (setjmp (g_env) == 1)
    return;

  label_decl ();
  expression ();

  return;
}
