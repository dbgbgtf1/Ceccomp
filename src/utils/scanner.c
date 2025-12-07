#include "scanner.h"
#include "log/logger.h"
#include "token.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static scanner_t scanner;

#define INIT_TOKEN(type) init_token (&scanner, type)
#define INIT_TOKEN_DATA(type, data) init_token_data (&scanner, type, data)

static bool
is_alpha (char c)
{
  if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
    return true;
  return false;
}

static inline bool
is_digit (char c)
{
  if (c >= '0' && c <= '9')
    return true;
  return false;
}

static inline bool
is_alnum (char c)
{
  if (is_alpha (c))
    return true;
  if (is_digit (c))
    return true;
  if (c == '_')
    return true;
  return false;
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
  if (match (' '))
    while (match (' '))
      ;

  // COMMENT
  if (match (*token_pairs[COMMENT]))
    while (peek () != '\n' && peek () != '\0')
      advance (1);

  // sync
  scanner.token_start = scanner.current_char;

  // EOF
  if (peek () == '\0')
    return INIT_TOKEN (TOKEN_EOF);

  // NEWLINE
  if (match (*token_pairs[NEWLINE]))
    {
      scanner.line_nr++;
      return INIT_TOKEN (NEWLINE);
    }

  // ARCH_X86 : TOKEN_EOF
  for (uint32_t enum_idx = (int)ARCH_X86; enum_idx < (int)UNKNOWN; enum_idx++)
    {
      if (match_string (token_pairs[enum_idx], strlen (token_pairs[enum_idx])))
        return INIT_TOKEN (enum_idx);
    }

  // LABEL_DECL : IDENTIFIER
  // IDENTIFIER include SYSCALL and label
  // We don't want hash the SYSCALL, so leave it later
  if (is_alpha (peek ()))
    {
      do
        advance (1);
      while (is_alnum (peek ()));

      return INIT_TOKEN (match (':') ? LABEL_DECL : IDENTIFIER);
    }

  // NUMBER
  if (isdigit (peek ()))
    {
      char *end;
      errno = 0;
      uint32_t num = strtol (scanner.token_start, &end, 0);
      if (errno)
        error ("strtol: %s", strerror (errno));
      scanner.current_char = end;
      return INIT_TOKEN_DATA (NUMBER, num);
    }

  return INIT_TOKEN (UNKNOWN);
}
