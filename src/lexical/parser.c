#include "parser.h"
#include "arch_trans.h"
#include "hash.h"
#include "log/error.h"
#include "scanner.h"
#include "token.h"
#include <seccomp.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
  uint16_t text_nr;
  uint16_t code_nr;

  token_t previous;
  token_t current;
  token_t next;
} parser_t;

static parser_t parser = { .text_nr = -1, .code_nr = -1 };
static statement_t *local;
static uint32_t local_arch;
static jmp_buf g_env;

static void
advance ()
{
  parser.previous = parser.current;
  parser.current = parser.next;
  scan_token (&parser.next);
}

static bool
peek (token_type expected)
{
  if (expected != parser.next.type)
    return false;

  return true;
}

static bool
peek_from_to (token_type from, token_type to)
{
  if (parser.next.type < from || parser.next.type > to)
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
  // sync to the nextline
  while (!(match (EOL) || peek (TOKEN_EOF)))
    advance ();

  local->type = ERROR_LINE;
  local->line_end = parser.current.token_start + parser.current.token_len;
  local->error_line.error_start = token.token_start;
  local->error_line.error_msg = err_msg;
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
  parser.code_nr--;
  // empty_line doesn't count
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

  if (match_from_to (TRACE, ERRNO))
    {
      obj->type = parser.current.type;
      obj->data = paren_num ();
    }
  else if (match (NUMBER))
    {
      obj->type = NUMBER;
      obj->data = parser.current.data;
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

  label->type = IDENTIFIER;
  label->key.string = parser.current.token_start;
  label->key.len = parser.current.token_len;
}

static uint32_t
resolve_name_arch (uint32_t arch_token, token_t *sys_token)
{
  char *sys_name = strndup (sys_token->token_start, sys_token->token_len);
  uint32_t sys_nr = seccomp_syscall_resolve_name_arch (arch_token, sys_name);
  free (sys_name);
  return sys_nr;
}

static void
compare_obj (obj_t *obj)
{
  if (match (X))
    {
      obj->type = parser.current.type;
      return;
    }

  obj->type = NUMBER;

  if (match (NUMBER))
    {
      obj->data = parser.current.data;
      return;
    }

  if (match (IDENTIFIER))
    {
      obj->data = resolve_name_arch (local_arch, &parser.current);
      if (obj->data == (uint32_t)-1)
        error_at (parser.current, EXPECT_SYSCALL);
      return;
    }
  // read

  if (!match_from_to (ARCH_X86, ARCH_RISCV64))
    error_at (parser.next, UNEXPECT_TOKEN);

  if (!match (DOT))
    {
      obj->data = internal_arch_to_scmp_arch (parser.current.type);
      return;
    }
  // i386

  if (!peek (IDENTIFIER))
    error_at (parser.next, EXPECT_SYSCALL);

  uint32_t scmp_arch = internal_arch_to_scmp_arch (parser.previous.type);
  obj->data = resolve_name_arch (scmp_arch, &parser.next);
  if (obj->data == (uint32_t)-1)
    error_at (parser.next, EXPECT_SYSCALL);

  advance ();
  // i386.read
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
  if (!match_from_to (EQUAL_EQUAL, AND))
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
  jump_line->jf.key.string = NULL;
  // jf default as zero

  if (peek (EOL) || peek (TOKEN_EOF))
    return;

  if (!jump_line->if_condition)
    error_at (parser.next, UNEXPECT_TOKEN);
  // without condition, there is no jf;

  if (!match (COMMA))
    error_at (parser.next, EXPECT_COMMA);
  if (!match (ELSE))
    error_at (parser.next, EXPECT_ELSE);
  if (!match (GOTO))
    error_at (parser.next, EXPECT_GOTO);

  label (&jump_line->jf);
}

static void
left (obj_t *obj)
{
  obj->type = parser.current.type;
  // expression checked for us, it must be A X MEM here

  if (parser.current.type == MEM)
    obj->data = bracket_num ();
}

static void
right (obj_t *obj)
{
  if (match (A) || match (X) || match_from_to (ATTR_LEN, ATTR_HIGHPC))
    obj->type = parser.current.type;
  else if (match (MEM) || match (ATTR_LOWARG) || match (ATTR_HIGHARG))
    {
      obj->type = parser.current.type;
      obj->data = bracket_num ();
    }
  else if (match (NUMBER))
    {
      obj->type = parser.current.type;
      obj->data = parser.current.data;
    }
  else
    error_at (parser.next, EXPECT_RIGHT_VAR);
}

static void
assign_line ()
{
  local->type = ASSIGN_LINE;
  assign_line_t *assign_line = &local->assign_line;

  left (&assign_line->left_var);

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

  right (&assign_line->right_var);
}

static void
expression ()
{
  if (peek (EOL))
    empty_line ();
  else if (peek (TOKEN_EOF))
    eof_line ();
  else if (match (RETURN))
    return_line ();
  else if (match (IF) || peek (GOTO))
    jump_line ();
  else if (match_from_to (A, MEM))
    assign_line ();
  else
    error_at (parser.next, UNEXPECT_TOKEN);

  if (match (EOL))
    local->line_end = parser.current.token_start;
  else if (peek (TOKEN_EOF))
    local->line_end = parser.next.token_start;
  else
    error_at (parser.next, UNEXPECT_TOKEN);
}

static void
label_decl ()
{
  if (!match (LABEL_DECL))
    return;

  label_t label;
  label.type = IDENTIFIER;
  label.key.string = parser.current.token_start;
  label.key.len = parser.current.token_len - 1;
  // ignore the ':' character
  insert_key (&label.key, parser.code_nr);

  // ignore our disasm useless output
  uint32_t count = 0;
  while (match (NUMBER) && count < 4)
    count++;
}

void
init_parser (uint32_t scmp_arch)
{
  advance ();
  local_arch = scmp_arch;
}

void
parse_line (statement_t *statement)
{
  local = statement;
  memset (local, '\0', sizeof (statement_t));

  parser.text_nr++;
  parser.code_nr++;
  // if statement turns out to be empty_line, code_line--;
  local->code_nr = parser.code_nr;
  local->text_nr = parser.text_nr;

  local->line_start = parser.next.token_start;

  if (setjmp (g_env) == 1)
    return;

  label_decl ();
  expression ();

  return;
}
