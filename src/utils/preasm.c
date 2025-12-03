#include "preasm.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include <errno.h>
#include <fcntl.h>
#include <seccomp.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define LINE_LEN 0x400

static char clean_line[LINE_LEN];
static char origin_line[LINE_LEN];

static char *
get_line (FILE *fp)
{
  if (fgets (origin_line, LINE_LEN, fp) == NULL)
    {
      if (feof (fp))
        return NULL;

      error ("fgets: %s", strerror (errno));
    }

  uint32_t len = strlen (origin_line);

  if (origin_line[len - 1] == '\n')
    origin_line[len - 1] = '\0';
  else if (len == (LINE_LEN - 1))
    error ("%s: %s", LINE_TOO_LONG, origin_line);

  return origin_line;
}

static bool
is_etc (char *Line)
{
  if (STARTWITH (Line, "----------------------------------"))
    return true;
  else if (STARTWITH (Line, " Label  CODE  JT   JF      K"))
    return true;
  else if (STARTWITH (Line, "LabelCODEJTJFK"))
    return true;
  return false;
}

static char *
get_valid_line (char *text)
{
  char *start = NULL;
  if ((start = strstr (text, "if")) != NULL)
    return start;

  if ((start = strstr (text, "return")) != NULL)
    return start;

  if ((start = strstr (text, "goto")) != NULL)
    return start;

  if ((start = strchr (text, '$')) != NULL)
    return start;

  if (is_etc (text))
    return "";

  error ("%s: %s", INVALID_ASM_CODE, text);
}

void
clear_color (char *text)
{
  char *colorstart = NULL;
  char *clear = text;

  for (char *cursor = text; *cursor != '\0'; cursor++)
    {
      if (!colorstart && *cursor != '\x1b')
        *clear++ = *cursor;
      else if (!colorstart && *cursor == '\x1b')
        colorstart = cursor;
      else if (colorstart && *cursor == 'm')
        colorstart = NULL;
      // else skip
    }
  *clear = '\0';
}

static void
clear_space (char *text)
{
  char *stripped = text;

  for (char *cursor = text; *cursor != '\0'; cursor++)
    if (*cursor != ' ')
      *stripped++ = *cursor;
  *stripped = '\0';
}

// origin_line = NULL if EOF
void
pre_asm (FILE *read_fp, char **origin, char **clean)
{
  while (get_line (read_fp) != NULL)
    {
      clear_color (origin_line);
      *origin = get_valid_line (origin_line);
      if (**origin == '\0')
        continue;

      strncpy (clean_line, *origin, LINE_LEN);
      clear_space (clean_line);
      *clean = clean_line;
      return;
    }

  *origin = NULL;
}
