#include "scanner.h"
#include "token.h"
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

scanner_t scanner;

#define INIT_TOKEN(type) init_token (&scanner, type)
#define INIT_TOKEN_DATA(type, data) init_token_data (&scanner, type, data)

static char
peek (uint8_t len)
{
  return scanner.current_char[len];
}

static void
advance (uint16_t advance_len)
{
  scanner.current_char += advance_len;
}

static bool
match_string (char *expected)
{
  uint16_t compare_len = strlen (expected);
  if (strncmp (expected, scanner.current_char, compare_len))
    return false;
  advance (compare_len);
  return true;
}

void
init_scanner (char *start)
{
  scanner.token_start = start;
  scanner.current_char = start;
  scanner.line_nr = 1;
}

token_t
scan_token ()
{
  // spaces
  while (peek (0) == ' ' || peek (0) == '-')
    advance (1);

  scanner.token_start = scanner.current_char;

  // COMMENT
  if (match_string (token_pairs[COMMENT]))
    {
      while (peek (0) != '\n' && peek (0) != '\0')
        advance (1);
      return INIT_TOKEN (COMMENT);
    }

  // NEWLINE
  if (match_string (token_pairs[NEWLINE]))
    {
      scanner.line_nr++;
      return INIT_TOKEN (NEWLINE);
    }

  // ARCH_X86 : TOKEN_EOF
  for (uint32_t enum_idx = (int)ARCH_X86; enum_idx < (int)NEWLINE + 1;
       enum_idx++)
    {
      if (match_string (token_pairs[enum_idx]))
        return INIT_TOKEN (enum_idx);
    }

  // LABEL_DECL : IDENTIFIER
  if (isalpha (peek (0)))
    {
      do
        advance (1);
      while (isalnum (peek (0)));

      return INIT_TOKEN (match_string (":") ? LABEL_DECL : IDENTIFIER);
    }

  // NUMBER
  if (isdigit (peek (0)))
    {
      do
        advance (1);
      while (isdigit (peek (0)));
      char *end;
      uint32_t num = strtol (scanner.token_start, &end, 0);
      return INIT_TOKEN_DATA (NUMBER, num);
    }

  return INIT_TOKEN (UNKNOWN);
}
