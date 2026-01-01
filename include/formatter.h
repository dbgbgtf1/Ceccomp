#ifndef FORMATTER
#define FORMATTER

#include "parser.h"

#define DEFAULT_LABEL "L%04d"

typedef void (*print_fn) (token_type type, uint32_t data);

extern void print_obj (obj_t *obj);

// this should be called in order
// call deresolve_statement before print_statement
extern void print_statement (statement_t *statement);

#endif
