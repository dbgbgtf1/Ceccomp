#ifndef FORMATTER_H
#define FORMATTER_H

#include "lexical/parser.h"
#include <stdio.h>

#define DEFAULT_LABEL "L%04d"

typedef void (*print_fn) (obj_t *obj);

typedef struct
{
  print_fn handler;
  char *color;
} obj_print_t;

extern void extern_obj_printer (FILE *output_fp, obj_t *obj);

extern void print_as_comment (FILE *output_fp, const char *comment_fmt, ...)
    __attribute__ ((format (printf, 2, 3)));

extern void print_statement (FILE *output_fp, statement_t *statement);

#endif
