#include "formatter.h"
#include "color.h"
#include "parser.h"
#include "token.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void
print_num (token_type type, uint32_t data)
{
  (void)type;
  printf (BRIGHT_CYAN ("0x%x"), data);
}

static void
print_var (token_type type, uint32_t data)
{
  (void)data;
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
  (void)data;
  printf (BRIGHT_BLUE ("%s"), token_pairs[type]);
}

static void
print_red (token_type type, uint32_t data)
{
  (void)data;
  printf (RED ("%s"), token_pairs[type]);
}

static void
print_yellow (token_type type, uint32_t data)
{
  (void)data;
  printf (YELLOW ("%s"), token_pairs[type]);
}

static void
print_yellow_paren (token_type type, uint32_t data)
{
  printf (YELLOW ("%s"), token_pairs[type]);
  if (data)
    printf ("(0x%x)", data);
}

static void
print_green (token_type type, uint32_t data)
{
  (void)data;
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
  [TRACE] = print_yellow_paren,
  [TRAP] = print_yellow_paren,
  [ERRNO] = print_yellow_paren,
};

void
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
  putchar (' ');
  if (assign_line->operator == NEGATIVE)
    printf ("= -");
  else
    {
      print_token_pair (assign_line->operator);
      putchar (' ');
    }

  print_obj (right);
}

static inline void
print_label (label_t *label, uint16_t pc)
{
  if (label->key.start == NULL)
    printf (DEFAULT_LABEL, pc + label->code_nr + 1);
  else
    printf ("%.*s", label->key.len, label->key.start);
}

static void
print_ja (statement_t *statement)
{
  print_token_pair (GOTO);
  putchar (' ');
  print_label (&statement->jump_line.jt, statement->code_nr);
}

static void
jump_line (statement_t *statement)
{
  jump_line_t *jump_line = &statement->jump_line;
  if (!jump_line->if_condition)
    return print_ja (statement);

  print_token_pair (IF);
  putchar (' ');
  if (jump_line->if_bang)
    print_token_pair (BANG);
  print_token_pair (LEFT_PAREN);
  obj_t obj_A = { .type = A, .data = 0 };
  print_obj (&obj_A);
  putchar (' ');
  print_token_pair (jump_line->cond.comparator);
  putchar (' ');
  print_obj (&jump_line->cond.cmpobj);
  print_token_pair (RIGHT_PAREN);
  putchar (' ');
  print_token_pair (GOTO);
  putchar (' ');
  print_label (&jump_line->jt, statement->code_nr);

  if (jump_line->jf.code_nr == 0)
    return;

  print_token_pair (COMMA);
  putchar (' ');
  print_token_pair (ELSE);
  putchar (' ');
  print_token_pair (GOTO);
  putchar (' ');
  print_label (&jump_line->jf, statement->code_nr);
}

static void
return_line (statement_t *statement)
{
  print_token_pair (RETURN);
  putchar (' ');
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
    case EMPTY_LINE:
    case ERROR_LINE:
    case EOF_LINE:
      assert (0);
    }
  putchar ('\n');
}
