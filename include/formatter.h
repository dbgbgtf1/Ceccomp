#ifndef FORMATTER
#define FORMATTER

#include "parser.h"

#define DEFAULT_LABEL "L%04d"

typedef void (*print_fn) (token_type type, uint32_t data);

typedef struct {
  print_fn handler;
  char *color;
} obj_print_t;

extern void obj_printer (obj_t *obj);

// this should be called in order
// call deresolve_statement before print_statement
extern void print_statement (statement_t *statement);

#endif
