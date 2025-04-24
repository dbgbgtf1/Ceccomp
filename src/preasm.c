#include "preasm.h"
#include "Main.h"
#include "error.h"
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

bool
isEtc (char *Line)
{
  if (STARTWITH (Line, "---------------------------------"))
    return true;
  else if (STARTWITH (Line, " Line  CODE  JT   JF      K"))
    return true;
  else if (STARTWITH (Line, "child process status: "))
    return true;
  return false;
}
char *
RetLines (FILE *fp)
{
  char *Line = NULL;
  size_t read = 0;
  size_t len = 0;

  read = getline (&Line, &len, fp);

  if (read != -1)
    {
      if (Line[read - 1] == '\n')
        Line[read - 1] = '\0';

      char *start = NULL;
      if ((start = strstr (Line, "if")) != NULL)
        return start;

      else if ((start = strstr (Line, "ret")) != NULL)
        return start;

      else if ((start = strchr (Line, '$')) != NULL)
        return start;

      else if (!isEtc (Line))
        PEXIT ("Error Line: %s", Line);

      return "";
    }

  return NULL;
}

void
ClearColor (char *Line)
{
  char *colorstart = NULL;
  char *colorend = NULL;

  while ((colorstart = strchr (Line, '\e')) != NULL)
    {
      colorend = strchr (colorstart, 'm');
      memset (colorstart, ' ', colorend - colorstart + 1);
    }
}

void
ClearSpace (char *Line)
{
  char *space = NULL;
  char *spaceend = NULL;

  while ((space = strchr (Line, ' ')) != NULL)
    {
      spaceend = space;
      while (*spaceend == ' ')
        spaceend = spaceend + 1;
      sprintf (space, "%s", spaceend);
    }
}

char *
PreAsm (FILE *fp)
{
  char *Line;
  do
    {
      Line = RetLines (fp);
      if (Line == NULL)
        return Line;
    }
  while (*Line == '\0');

  ClearColor (Line);
  ClearSpace (Line);

  return Line;
}
