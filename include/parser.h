#ifndef PARSER
#define PARSER

#include "hash.h"
#include "main.h"
#include "token.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
  token_type type;
  union {
    hkey_t key;
    uint32_t code_nr;
  };
  // store code_nr when type is NUMBER
  // store identifier when type is IDENTIFIER
}label_t;

typedef struct
{
  token_type type;
  union
  {
    uint32_t data;
    string_t string;
  };
  // store idx for MEM | ATTR_LOWARG | ATTR_HIGHARG
  // store value for NUMBER | TRAP | TRACE | ERRNO
  // use ATTR_SYSCALL to cover read
  // I can't deal with `read` in parser without arch
  // so save it in string
} obj_t;

typedef struct
{
  obj_t left_var;
  token_type operator;
  obj_t right_var;
  // if operator is NEGATIVE, then it should be A EQUAL NEGATIVE A
  // but EQUAL is skipped
} assign_line_t;

typedef struct
{
  // var A;
  // jump always compare A with something else, so skip it
  token_type comparator;
  obj_t cmpobj;
} jump_condition_t;

typedef struct
{
  // token_t if;
  // jump_line_t must starts with if, so skip it
  bool if_bang;
  // if match '!' before jump_condition
  bool if_condition;
  // does condition exists
  // if true, jt and jf both uint16_t
  // else jt is uint32_t, jf is ignored
  jump_condition_t cond;

  label_t jt;
  label_t jf;
  // pc += (jump_condition ? jt : jf) + 1
  // pc += jt + 1
} jump_line_t;

typedef struct
{
  // token_type return
  // return_line_t must have return, so skip it
  obj_t ret_obj;
} return_line_t;

typedef void *empty_line_t;
typedef void *eof_line_t;

typedef struct
{
  char *error_start;
  char *error_msg;
} error_line_t;

typedef enum
{
  ASSIGN_LINE,
  JUMP_LINE,
  RETURN_LINE,
  EMPTY_LINE,
  EOF_LINE,
  ERROR_LINE,
} expr_type;

typedef struct
{
  uint16_t text_nr;
  uint16_t code_nr;
  expr_type type;
  char *line_start;
  char *line_end;

  union
  {
    assign_line_t assign_line;
    jump_line_t jump_line;
    return_line_t return_line;
    empty_line_t empty_line;
    eof_line_t eof_line;
    error_line_t error_line;
  };
} statement_t;

extern void init_parser ();

extern void parse_line (statement_t *statement);

#endif
