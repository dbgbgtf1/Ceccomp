#include "print_statement.h"
#include "color.h"
#include "parser.h"
#include "token.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

typedef void (*print_fn) (token_type type, uint32_t data);

static void
print_num (token_type type, uint32_t data)
{
  printf (BRIGHT_CYAN ("0x%x"), data);
}

static void
print_var (token_type type, uint32_t data)
{
  printf (BRIGHT_YELLOW ("%s"), token_pairs[type]);
}

static void
print_mem (token_type type, uint32_t data)
{
  printf (BRIGHT_YELLOW ("%s[0x%01x]"), token_pairs[type], data);
}

static void
print_attr_bracket (token_type type, uint32_t data)
{
  printf (BRIGHT_BLUE ("%s[0x%01x]"), token_pairs[type], data);
}

static void
print_attr (token_type type, uint32_t data)
{
  printf (BRIGHT_BLUE ("%s"), token_pairs[type]);
}

static void
print_red (token_type type, uint32_t data)
{
  printf (RED ("%s"), token_pairs[type]);
}

static void
print_yellow (token_type type, uint32_t data)
{
  printf (YELLOW ("%s"), token_pairs[type]);
}

static void
print_green (token_type type, uint32_t data)
{
  printf (GREEN ("%s"), token_pairs[type]);
}

print_fn obj_printer[] = {
  [A] = print_var,
  [X] = print_var,

  [MEM] = print_mem,
  [ATTR_LOWARG] = print_attr_bracket,
  [ATTR_HIGHARG] = print_attr_bracket,

  [ATTR_SYSCALL] = print_attr,
  [ATTR_ARCH] = print_attr,
  [ATTR_LOWPC] = print_attr,
  [ATTR_HIGHPC] = print_attr,

  [NUMBER] = print_num,

  [KILL_PROC] = print_red,
  [KILL] = print_red,
  [ALLOW] = print_green,
  [NOTIFY] = print_yellow,
  [LOG] = print_yellow,
  [TRACE] = print_yellow,
  [TRAP] = print_yellow,
  [ERRNO] = print_yellow,
};

static inline void
print_obj (obj_t *obj)
{
  obj_printer[obj->type](obj->type, obj->data);
}

static inline void
print_token_pair (token_type type)
{
  printf ("%s", token_pairs[type]);
}

static void
assign_line (statement_t *statement)
{
  assign_line_t *assign_line = &statement->assign_line;
  obj_t *left = &assign_line->left_var;
  obj_t *right = &assign_line->right_var;

  print_obj (left);
  printf (" ");
  if (assign_line->operator == NEGATIVE)
    printf ("= -");
  else
    print_token_pair (assign_line->operator);

  print_obj (right);
}

static inline void
print_label (uint32_t jump_to)
{
  printf (DEFAULT_LABEL, jump_to);
}

static void
print_ja (statement_t *statement)
{
  uint32_t jt = statement->code_nr + statement->jump_line.jt.code_nr + 1;

  print_token_pair (GOTO);
  printf (" ");
  print_label (jt);
}

static void
jump_line (statement_t *statement)
{
  jump_line_t *jump_line = &statement->jump_line;
  if (!jump_line->if_condition)
    print_ja (statement);

  uint16_t jt = statement->code_nr + jump_line->jt.code_nr + 1;
  uint16_t jf = statement->code_nr + jump_line->jf.code_nr + 1;

  print_token_pair (IF);
  printf (" ");
  if (jump_line->if_bang)
    print_token_pair (BANG);
  print_token_pair (LEFT_PAREN);
  print_token_pair (A);
  printf (" ");
  print_token_pair (jump_line->cond.comparator);
  print_obj (&jump_line->cond.cmpobj);
  print_token_pair (RIGHT_PAREN);
  printf (" ");
  print_token_pair (GOTO);
  printf (" ");
  print_label (jt);

  if (jump_line->jf.code_nr == 0)
    return;

  print_token_pair (COMMA);
  printf (" ");
  print_token_pair (ELSE);
  printf (" ");
  print_token_pair (GOTO);
  printf (" ");
  print_label (jf);
}

static void
return_line (statement_t *statement)
{
  print_token_pair (RETURN);
  printf (" ");
  print_obj (&statement->return_line.ret_obj);
}

void
print_statement (statement_t *statement)
{
  switch (statement->type)
    {
    case ASSIGN_LINE:
      assign_line (statement);
      break;
    case JUMP_LINE:
      jump_line (statement);
      break;
    case RETURN_LINE:
      return_line (statement);
      break;
    default:
      assert (0);
    }
}
