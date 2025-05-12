#include "preasm.h"
#include "error.h"
#include "main.h"
#include <fcntl.h>
#include <seccomp.h>
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
  else if (STARTWITH (Line, " Line  CODE  JT   JF      K"))
    return true;
  else if (STARTWITH (Line, "child process status: "))
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

  if (read != -1)
    {
      if (origin_line[read - 1] == '\n')
        origin_line[read - 1] = '\0';

      char *start = NULL;
      if ((start = strstr (origin_line, "if")) != NULL)
        return start;

      else if ((start = strstr (origin_line, "ret")) != NULL)
        return start;

      else if ((start = strchr (origin_line, '$')) != NULL)
        return start;

      else if (!is_etc (origin_line))
        PEXIT (INVALID_ASM_CODE ": %s", origin_line);

      return "";
    }

  return NULL;
}

static void
pre_clear_color (char *clean_line)
{
  char *colorstart = NULL;
  char *colorend = NULL;

  while ((colorstart = strchr (clean_line, '\e')) != NULL)
    {
      colorend = strchr (colorstart, 'm');
      memset (colorstart, ' ', colorend - colorstart + 1);
    }
}

static void
pre_clear_space (char *clean_line)
{
  char *space = NULL;
  char *spaceend = NULL;

  while ((space = strchr (clean_line, ' ')) != NULL)
    {
      spaceend = space;
      while (*spaceend == ' ')
        spaceend = spaceend + 1;
      char *copy = strdup (spaceend);
      strcpy (space, copy);
      free (copy);
    }
}

void
pre_asm (FILE *fp, line_set *Line)
{
  do
    {
      Line->origin_line = pre_get_lines (fp);
      if (Line->origin_line == NULL)
        return;
    }
  while (*Line->origin_line == '\0');

  Line->clean_line = strdup (Line->origin_line);

  pre_clear_color (Line->clean_line);
  pre_clear_space (Line->clean_line);
}
