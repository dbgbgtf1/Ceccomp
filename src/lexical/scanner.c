#include "scanner.h"
#include "log/logger.h"
#include "read_source.h"
#include "token.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static scanner_t scanner;
static uint8_t unknown_count = 0;

#define INIT_TOKEN(type)                                                      \
  do                                                                          \
    {                                                                         \
      init_token (token, &scanner, type);                                     \
      return;                                                                 \
    }                                                                         \
  while (0)
#define INIT_TOKEN_DATA(type, data)                                           \
  do                                                                          \
    {                                                                         \
      init_token_data (token, &scanner, type, data);                          \
      return;                                                                 \
    }                                                                         \
  while (0)

static inline bool
isidentifier (char c)
{
  return isalnum (c) || c == '_';
}

static char
peek ()
{
  return scanner.current_char[0];
}

static void
advance (uint16_t advance_len)
{
  scanner.current_char += advance_len;
}

static bool
match (char expected)
{
  if (peek () != expected)
    return false;

  advance (1);
  return true;
}

static bool
match_string (char *expected, uint16_t cmp_len)
{
  if (strncmp (expected, scanner.current_char, cmp_len))
    return false;

  advance (cmp_len);
  return true;
}

static void
reset_to_nextline (token_t *token)
{
  char *nextline = next_line ();
  if (nextline == NULL)
    INIT_TOKEN (TOKEN_EOF);

  init_token (token, &scanner, EOL);
  scanner.token_start = nextline;
  scanner.current_char = scanner.token_start;
  scanner.line_nr++;
}

static void
skip_spaces ()
{
  // spaces
  while (isspace (peek ()) && peek () != '\n')
    advance (1);
}

void
init_scanner (char *start)
{
  scanner.token_start = start;
  scanner.current_char = start;
  scanner.line_nr = 1;
}

void
scan_token (token_t *token)
{
  // skip spaces
  skip_spaces ();

  // sync
  scanner.token_start = scanner.current_char;

  // COMMENT
  if (match (*token_pairs[COMMENT]))
    {
      while (peek () != '\n')
        advance (1);
      INIT_TOKEN (COMMENT);
    }

  // EOL
  if (peek () == '\n')
    return reset_to_nextline (token);

  // ARCH_X86 : TOKEN_EOF
  for (uint32_t enum_idx = (int)ARCH_X86; enum_idx < (int)UNKNOWN; enum_idx++)
    {
      if (match_string (token_pairs[enum_idx], strlen (token_pairs[enum_idx])))
        INIT_TOKEN (enum_idx);
    }

  // LABEL_DECL : IDENTIFIER
  // IDENTIFIER include SYSCALL and label
  // We don't want hash the SYSCALL, so leave it later
  if (isalpha (peek ()))
    {
      do
        advance (1);
      while (isidentifier (peek ()));

      INIT_TOKEN (match (':') ? LABEL_DECL : IDENTIFIER);
    }

  // NUMBER
  if (isxdigit (peek ()))
    {
      char *end;
      errno = 0;
      uint32_t num = strtol (scanner.token_start, &end, 0);
      if (errno)
        error ("strtol: %s", strerror (errno));
      scanner.current_char = end;
      INIT_TOKEN_DATA (NUMBER, num);
    }

  // perhaps that's a wrong file? tell parser to stop using EOF
  if (unknown_count > 5)
    INIT_TOKEN (TOKEN_EOF);

  unknown_count += 1;
  advance (1);
  INIT_TOKEN (UNKNOWN);
}
