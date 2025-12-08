#include "parse_args.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ceccomp_args args;

static struct argp_option options[] = {
  { "quiet", 'q', NULL, 0, NULL, 0 },
  { "color", 'c', "COLOR", 0, NULL, 0 },
  { "output", 'o', "OUTPUT", 0, NULL, 0 },
  { "arch", 'a', "ARCH", 0, NULL, 0 },
  { "pid", 'p', "PID", 0, NULL, 0 },
  { "fmt", 'f', "FMT", 0, NULL, 0 },
  { "help", 'h', NULL, 0, NULL, 0 },
  { "usage", 'u', NULL, 0, NULL, 0 },
  { 0 },
};

static void
init_args (ceccomp_args *args)
{
  memset (args, '\0', sizeof (ceccomp_args));
  args->cmd = HELP_ABNORMAL;
  char *no_color = getenv ("NO_COLOR");
  if (no_color != NULL && no_color[0] != '\0')
    args->when = NEVER;
  else
    args->when = AUTO;
}

int
main (int argc, char *argv[])
{
  init_args (&args);

  static struct argp argp
      = { options, parse_opt, NULL, NULL, NULL, NULL, NULL };
  argp_parse (&argp, argc, argv, ARGP_IN_ORDER, 0, &args);

  printf ("cmd: %d\n", args.cmd);
  printf ("color: %d\n", args.when);
}
