#include "preasm.h"
#include "log/error.h"
#include "main.h"
#include <fcntl.h>
#include <seccomp.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static bool
is_etc (char *Line)
{
  if (STARTWITH (Line, "---------------------------------"))
    return true;
  else if (STARTWITH (Line, "LineCODEJTJFK"))
    return true;
  return false;
}

static char *
pre_get_lines (FILE *fp)
{
  char *origin_line = NULL;
  size_t read = 0;
  size_t len = 0;

  read = getline (&origin_line, &len, fp);

  if (read != (size_t)-1)
    {
      if (origin_line[read - 1] == '\n')
        origin_line[read - 1] = '\0';
      return origin_line;
    }

  return NULL;
}

void
pre_clear_color (char *clean_line)
{
  char *colorstart = NULL;
  char *clear = clean_line;

  for (char *cursor = clean_line; *cursor != '\0'; cursor++)
    {
      if (!colorstart && *cursor != '\e')
        *clear++ = *cursor;
      else if (!colorstart && *cursor == '\e')
        colorstart = cursor;
      else if (colorstart && *cursor == 'm')
        colorstart = NULL;
      // else skip
    }
  *clear = '\0';
}

static void
pre_clear_space (char *clean_line)
{
  char *stripped = clean_line;

  for (char *cursor = clean_line; *cursor != '\0'; cursor++)
    if (*cursor != ' ')
      *stripped++ = *cursor;
  *stripped = '\0';
}

static char *
check_valid_line (char *clean_line)
{
  char *start = NULL;
  if ((start = strstr (clean_line, "if")) != NULL)
    return start;

  if ((start = strstr (clean_line, "return")) != NULL)
    return start;

  if ((start = strstr (clean_line, "goto")) != NULL)
    return start;

  if ((start = strchr (clean_line, '$')) != NULL)
    return start;

  if (is_etc (clean_line))
    return "";

  PEXIT (INVALID_ASM_CODE ": %s", clean_line);
}

static char *copy_line;

void
free_line (line_set *Line)
{
  if (copy_line)
    free (copy_line);
  if (Line->origin_line)
    free (Line->origin_line);
}

void
pre_asm (FILE *read_fp, line_set *Line)
{
  do
    {
      Line->origin_line = pre_get_lines (read_fp);
      if (Line->origin_line == NULL)
        return;
      copy_line = strdup (Line->origin_line);
      Line->clean_line = copy_line;

      pre_clear_color (Line->clean_line);
      pre_clear_space (Line->clean_line);

      Line->clean_line = check_valid_line (copy_line);
    }
  while (*Line->clean_line == '\0');
}
