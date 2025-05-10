#include "parseargs.h"
#include "error.h"
#include "main.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *
parse_option (int argc, char *argv[], char *token)
{
  for (int i = 0; i < argc; i++)
    {
      bool is_arg = STARTWITH (argv[i], "--");
      if (!is_arg)
        continue;

      char *arg = STRAFTER (argv[i], "--");
      bool is_token = STARTWITH (arg, token);
      if (!is_token)
        continue;

      arg = STRAFTER (arg, token);
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
    if (STARTWITH(argv[i], "--"))
      continue;
    return argv[i++];
  }
  PEXIT("%s\n", NOT_ENOUGH_ARGS);
}
