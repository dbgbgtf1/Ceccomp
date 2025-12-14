#include "debug_method.h"
#include "log/logger.h"
#include "parser.h"
#include "token.h"
#include <stdint.h>
#include <stdio.h>

void
print_token (token_t *token)
{
  if (token->type == EOL)
    debug ("At %04d: EOL", token->line_nr);
  else
    debug ("At %04d: %s", token->line_nr, token_pairs[token->type]);
}

#define SPRINTF_CAT(...) print += sprintf (__VA_ARGS__)

static char buf[0x400];
static char *print;

void
print_statement (statement_t *statement)
{
  print = buf;

  assign_line_t assign_line = statement->assign_line;
  jump_line_t jump_line = statement->jump_line;
  return_line_t return_line = statement->return_line;
  error_line_t error_line = statement->error_line;

  SPRINTF_CAT (print, "At %04d(%04d): ", statement->code_nr,
               statement->text_nr);
  switch (statement->type)
    {
    case ASSIGN_LINE:
      SPRINTF_CAT (print, "assign_line: ");
      SPRINTF_CAT (print, "%s %s %s", token_pairs[assign_line.left_var.type],
                   token_pairs[assign_line.operator],
                   token_pairs[assign_line.right_var.type]);
      break;
    case JUMP_LINE:
      SPRINTF_CAT (print, "jump_line: ");

      if (jump_line.if_condition)
        {
          SPRINTF_CAT (print, "if ");
          if (jump_line.if_bang)
            SPRINTF_CAT (print, "!");
          SPRINTF_CAT (print, "(A %s 0x%08x) ",
                       token_pairs[jump_line.cond.comparator],
                       jump_line.cond.cmpobj.data);
        }
      SPRINTF_CAT (print, "goto %04u",
                   jump_line.jt.code_nr + statement->code_nr + 1);
      if (jump_line.jf.key.string)
        SPRINTF_CAT (print, ", else goto %04u",
                     jump_line.jf.code_nr + statement->code_nr + 1);
      break;
    case RETURN_LINE:
      SPRINTF_CAT (print, "return_line: ");

      SPRINTF_CAT (print, "return %s", token_pairs[return_line.ret_obj.type]);
      if (return_line.ret_obj.data)
        SPRINTF_CAT (print, "(%d)", return_line.ret_obj.data);
      break;
    case EMPTY_LINE:
      SPRINTF_CAT (print, "empty_line: ");
      break;
    case EOF_LINE:
      SPRINTF_CAT (print, "eof_line: ");
      break;
    case ERROR_LINE:
      SPRINTF_CAT (print, "%s\n", error_line.error_msg);
      uint16_t line_len = statement->line_end - statement->line_start;
      uint16_t err_len = error_line.error_start - statement->line_start;
      SPRINTF_CAT (print, "%.*s\n", line_len, statement->line_start);
      SPRINTF_CAT (print, "%*s", err_len + 1, "^");
      break;
    default:
      SPRINTF_CAT (print, "impossible?");
      break;
    }

  printf ("%s\n", buf);
}

#undef SPRINTF_CAT
