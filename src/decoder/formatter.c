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
  printf ("0x%x", data);
}

static void
print_str (token_type type, uint32_t data)
{
  (void)data;
  printf ("%s", token_pairs[type]);
}

static void
print_bracket (token_type type, uint32_t data)
{
  printf ("%s[0x%01x]", token_pairs[type], data);
}

static void
print_paren (token_type type, uint32_t data)
{
  printf ("%s", token_pairs[type]);
  if (data)
    printf ("(0x%x)", data);
}

obj_print_t obj_print[] = {
  [A] = { print_str, BRIGHT_YELLOWCLR },
  [X] = { print_str, BRIGHT_YELLOWCLR },

  [MEM] = { print_bracket, BRIGHT_YELLOWCLR },
  [ATTR_LOWARG] = { print_bracket, BRIGHT_BLUECLR },
  [ATTR_HIGHARG] = { print_bracket, BRIGHT_BLUECLR },

  [ATTR_SYSCALL] = { print_str, BRIGHT_BLUECLR },
  [ATTR_ARCH] = { print_str, BRIGHT_BLUECLR },
  [ATTR_LOWPC] = { print_str, BRIGHT_BLUECLR },
  [ATTR_HIGHPC] = { print_str, BRIGHT_BLUECLR },

  [NUMBER] = { print_num, BRIGHT_CYANCLR },

  [KILL_PROC] = { print_str, REDCLR },
  [KILL] = { print_str, REDCLR },
  [ALLOW] = { print_str, GREENCLR },
  [NOTIFY] = { print_str, YELLOWCLR },
  [LOG] = { print_str, YELLOWCLR },
  [TRACE] = { print_paren, YELLOWCLR },
  [TRAP] = { print_paren, YELLOWCLR },
  [ERRNO] = { print_paren, REDCLR },
};

void
obj_printer (obj_t *obj)
{
  if (color_enable)
    printf ("%s", obj_print[obj->type].color);
  if (obj->literal.start != NULL)
    printf ("%.*s", obj->literal.len, obj->literal.start);
  else
    obj_print[obj->type].handler (obj->type, obj->data);
  if (color_enable)
    printf ("%s", CLR);
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

  obj_printer (left);
  putchar (' ');
  if (assign_line->operator == NEGATIVE)
    printf ("= -");
  else
    {
      print_token_pair (assign_line->operator);
      putchar (' ');
    }

  obj_printer (right);
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
  obj_printer (&obj_A);
  putchar (' ');
  print_token_pair (jump_line->cond.comparator);
  putchar (' ');
  obj_printer (&jump_line->cond.cmpobj);
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
  obj_printer (&statement->return_line.ret_obj);
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
      break;
    case ERROR_LINE:
    case EOF_LINE:
      assert (0);
    }
  putchar ('\n');
}
