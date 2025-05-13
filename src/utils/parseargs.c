#include "parseargs.h"
#include "error.h"
#include "main.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool
parse_option_enable (int argc, char *argv[], char *token)
{
  for (int i = 0; i < argc; i++)
    {
      char *arg = STRAFTER (argv[i], "--");
      if (arg == NULL)
        continue;

      arg = STRAFTER (arg, token);
      if (arg == NULL)
        continue;

      return true;
    }
  return false;
}

char *
parse_option_mode (int argc, char *argv[], char *token)
{
  for (int i = 0; i < argc; i++)
    {
      char *arg = STRAFTER (argv[i], "--");
      if (arg == NULL)
        continue;

      arg = STRAFTER (arg, token);
      if (arg == NULL)
        continue;

      if (*arg != '=')
        PEXIT (INVALID_ARG ":%s", argv[i]);

      return (arg + 1);
    }

  return NULL;
}

char *
get_arg (int argc, char *argv[])
{
  static int i = 0;
  for (; i < argc; i++)
    {
      if (STARTWITH (argv[i], "--"))
        continue;
      return argv[i++];
    }
  PEXIT ("%s\n", NOT_ENOUGH_ARGS);
}
