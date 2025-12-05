#include "debug_method.h"
#include "log/logger.h"
#include "parser.h"
#include "token.h"
#include <stdio.h>

void
print_token (token_t *token)
{
  if (token->type == NEWLINE)
    debug ("At %04d: NEWLINE", token->line_nr);
  else
    debug ("At %04d: %s", token->line_nr, token_pairs[token->type]);
}

#define SPRINTF(...) print += sprintf (__VA_ARGS__)

char buf[0x400];
char *print;

void
print_statement (state_ment_t *state_ment)
{
  print = buf;

  assign_line_t assign_line = state_ment->assign_line;
  jump_line_t jump_line = state_ment->jump_line;
  return_line_t return_line = state_ment->return_line;
  error_line_t error_line = state_ment->error_line;

  SPRINTF (print, "At %04d: ", state_ment->line_nr);
  switch (state_ment->type)
    {
    case ASSIGN_LINE:
      SPRINTF (print, "assign_line: ");
      SPRINTF (print, "%s %s %s;", token_pairs[assign_line.left_var.type],
               token_pairs[assign_line.operator],
               token_pairs[assign_line.right_var.type]);
      break;
    case JUMP_LINE:
      SPRINTF (print, "jump_line: ");

      if (jump_line.if_condition)
        {
          SPRINTF (print, "if ");
          if (jump_line.if_bang)
            SPRINTF (print, "!");
          SPRINTF (print, "(A %s %s) ", token_pairs[jump_line.cond.comparator],
                   token_pairs[jump_line.cond.cmpobj.type]);
        }
      SPRINTF (print, "goto %.*s", jump_line.jt.len, jump_line.jt.string);
      if (jump_line.jf.string)
        SPRINTF (print, ", else goto %.*s", jump_line.jf.len,
                 jump_line.jf.string);

      break;
    case RETURN_LINE:
      SPRINTF (print, "return_line: ");

      SPRINTF (print, "return %s", token_pairs[return_line.ret_obj.type]);
      if (return_line.ret_obj.data)
        SPRINTF (print, "(%d)", return_line.ret_obj.data);
      break;
    case EMPTY_LINE:
      SPRINTF (print, "empty_line: ");
      break;
    case EOF_LINE:
      SPRINTF (print, "eof_line: ");
      break;
    case ERROR_LINE:
      SPRINTF (print, "%s\n", error_line.error_msg);
      SPRINTF (print, "%*.s", error_line.offset, "^");
      break;
    default:
      SPRINTF (print, "impossible?");
      break;
    }

  debug ("%s", buf);
}
