#ifndef PARSER
#define PARSER

#include "hash.h"
#include "main.h"
#include "token.h"
#include <stdbool.h>
#include <stdint.h>

typedef hkey_t label_t;

#define LEN_VAL 0x40
// $scmp_data_len will be transfer to 0x40 as NUMBER
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
  // I don't want to deal with `i386 | i386.read | read` in parser
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
  char *line_start;
  char *line_end;
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
  uint16_t line_nr;
  expr_type type;

  union
  {
    assign_line_t assign_line;
    jump_line_t jump_line;
    return_line_t return_line;
    empty_line_t empty_line;
    eof_line_t eof_line;
    error_line_t error_line;
  };
} state_ment_t;

extern void init_parser ();

extern void parse_line (state_ment_t *state_ment);

#endif
