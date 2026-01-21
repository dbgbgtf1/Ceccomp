#ifndef SCANNER_H
#define SCANNER_H

#include "token.h"
#include <stdint.h>

struct scanner_t
{
  char *token_start;
  char *current_char;
  uint16_t line_nr;
};

typedef struct scanner_t scanner_t;
typedef struct token_t token_t;

extern void init_scanner (char *start);

extern void scan_token (token_t *token);

#endif
