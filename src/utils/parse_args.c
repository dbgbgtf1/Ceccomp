#include "parse_args.h"
#include "log/error.h"
#include "log/logger.h"
#include <argp.h>
#include <string.h>

static subcommand
parse_subcommand (char *arg)
{
  if (!strcmp (arg, "asm"))
    return ASM_MODE;
  else if (!strcmp (arg, "disasm"))
    return DISASM_MODE;
  else if (!strcmp (arg, "emu"))
    return EMU_MODE;
  else if (!strcmp (arg, "trace"))
    return TRACE_MODE;
  else if (!strcmp (arg, "probe"))
    return PROBE_MODE;
  else if (!strcmp (arg, "version"))
    return VERSION_MODE;
  else if (!strcmp (arg, "help"))
    return HELP_MODE;
  else
    return HELP_ABNORMAL;
}

static color_mode
parse_color_mode (char *arg)
{
  if (!strcmp (arg, "always"))
    return ALWAYS;
  else if (!strcmp (arg, "auto"))
    return AUTO;
  else if (!strcmp (arg, "never"))
    return NEVER;
  else
    error ("%s: %s", INVALID_COLOR_MODE, arg);
}

static int
parse_asm (asm_args *args, int key, char *arg)
{
  switch (key)
    {
    case ARGP_KEY_ARG:
      args->text_name = arg;
      return 0;
    case 'a':
      return 0;
    }

  return 0;
}

static int
parse_disasm (disasm_args *args, int key, char *arg)
{
  return 0;
}

static int
parse_emu (emu_args *args, int key, char *arg)
{
  return 0;
}

static int
parse_trace (trace_args *args, int key, char *arg)
{
  return 0;
}

static int
parse_probe (probe_args *args, int key, char *arg)
{
  return 0;
}

error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  ceccomp_args *args = state->input;

  switch (key)
    {
    case ARGP_KEY_ARG:
      if (state->arg_num == 0)
        args->cmd = parse_subcommand (arg);
      return 0;
    case 'c':
      args->when = parse_color_mode (arg);
    case 'h':
    case 'u':
      if (args->cmd == HELP_ABNORMAL)
        args->cmd = HELP_MODE;
      return 0;
    }

  if (args->cmd == ASM_MODE)
    return parse_asm (&args->asm_arg, key, arg);
  else if (args->cmd == DISASM_MODE)
    return parse_disasm (&args->disasm_arg, key, arg);
  else if (args->cmd == EMU_MODE)
    return parse_emu (&args->emu_arg, key, arg);
  else if (args->cmd == TRACE_MODE)
    return parse_trace (&args->trace_arg, key, arg);
  else if (args->cmd == PROBE_MODE)
    return parse_probe (&args->probe_arg, key, arg);

  return 0;
}
