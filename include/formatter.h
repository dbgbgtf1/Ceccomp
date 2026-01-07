#ifndef FORMATTER
#define FORMATTER

#include "parser.h"

#define DEFAULT_LABEL "L%04d"

typedef void (*print_fn) (token_type type, uint32_t data);

typedef struct
{
  print_fn handler;
  char *color;
} obj_print_t;

extern void obj_printer (obj_t *obj);

extern void print_as_comment (char *comment_fmt, ...)
    __attribute__ ((format (printf, 1, 2)));

extern void print_statement (statement_t *statement);

#endif
