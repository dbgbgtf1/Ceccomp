#include "parseargs.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include "transfer.h"
#include <argp.h>
#include <linux/ptrace.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint64_t
strtoull_check (char *num, int base, char *err)
{
  char *end;
  uint64_t ret = strtoull (num, &end, base);
  if (num == end)
    error ("%s: %s", err, num);
  return ret;
}

void
help (int exit_code)
{
  printf ("%s", CECCOMP_USAGE);
  putchar('\n');
  printf ("%s\n", ASM_HINT);
  printf ("%s\n", DISASM_HINT);
  printf ("%s\n", EMU_HINT);
  printf ("%s\n", PROBE_HINT);
  printf ("%s\n", TRACE_HINT);
  printf ("%s\n", HELP_HINT);
  printf ("%s\n", VERSION_HINT);

  printf ("\n%s\n", SUBCMD_HINT);

  printf ("\n%s\n", OPTION_HINT);
  exit (exit_code);
}

void
version ()
{
  printf ("%s\n", CECCOMP_VERSION);
  exit (0);
}

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

static print_mode
parse_print_mode (char *arg)
{
  if (!strcmp (arg, "hexline"))
    return HEXLINE;
  else if (!strcmp (arg, "hexfmt"))
    return HEXFMT;
  else if (!strcmp (arg, "raw"))
    return RAW;
  else
    error ("%s: %s", INVALID_PRINT_MODE, arg);
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

// asm and disasm share the same args logic
static void
asm_disasm_args (ceccomp_args *args_ptr, char *arg)
{
  static uint32_t arg_idx = 0;
  if (arg_idx != 0)
    return;
  arg_idx += 1;

  args_ptr->read_fp = fopen (arg, "r");
  if (args_ptr->read_fp == NULL)
    error ("%s: %s", UNABLE_OPEN_FILE, arg);
}

static void
emu_args (ceccomp_args *args_ptr, char *arg)
{
  static uint32_t arg_idx = 0;
  arg_idx += 1;

  if (arg_idx == 1)
    {
      args_ptr->read_fp = fopen (arg, "r");
      if (args_ptr->read_fp == NULL)
        error ("%s: %s", UNABLE_OPEN_FILE, arg);
    }
  else if (arg_idx == 2)
    args_ptr->syscall_nr = arg;
  else if ((arg_idx > 2) && (arg_idx < 9))
    args_ptr->sys_args[arg_idx - 3]
        = strtoull_check (arg, 0, INVALID_SYS_ARGS);
  else if (arg_idx == 9)
    args_ptr->ip = strtoull_check (arg, 0, INVALID_IP);
}

error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  ceccomp_args *args_ptr = state->input;

  if (args_ptr->program_idx != ARG_INIT_VAL)
    return 0;

  if (args_ptr->mode == TRACE_MODE)
    {
      if (key == ARGP_KEY_ARG)
        {
          args_ptr->mode = TRACE_PROG_MODE;
          args_ptr->program_idx = state->next - 1;
          return 0;
        }
      else if (key == 'p')
        args_ptr->mode = TRACE_PID_MODE;

      // we need to know whether it's trace-pid mode or trace-prog mode
      // so if we found '--pid' first, we decide it's trace-pid mode
      // else if we found arg first
      // we decide it's the trace-prog mode and this arg is program
      // whatever after this belongs to the tracee program args, we don't
      // parse them
    }

  switch (key)
    {
    case ARGP_KEY_ARG:
      if (state->arg_num == 0)
        args_ptr->mode = parse_subcommand (arg);
      else if (args_ptr->mode == PROBE_MODE)
        args_ptr->program_idx = state->next - 1;
      else if (args_ptr->mode == ASM_MODE || args_ptr->mode == DISASM_MODE)
        asm_disasm_args (args_ptr, arg);
      else if (args_ptr->mode == EMU_MODE)
        emu_args (args_ptr, arg);
      return 0;
    case 'q':
      args_ptr->quiet = true;
      return 0;
    case 'c':
      args_ptr->color = parse_color_mode (arg);
      return 0;
    case 'o':
      args_ptr->file_name = strdup (arg);
      return 0;
    case 'a':
      args_ptr->arch_token = STR2ARCH (arg);
      if (args_ptr->arch_token == (uint32_t)-1)
        error ("%s: %s\n%s", INVALID_ARCH, arg, SUPPORT_ARCH);
      return 0;
    case 'p':
      args_ptr->pid = strtoull_check (arg, 0, INVALID_PID);
      return 0;
    case 'f':
      args_ptr->fmt_mode = parse_print_mode (arg);
      return 0;
    case 'h':
      if (args_ptr->mode == HELP_ABNORMAL)
        args_ptr->mode = HELP_MODE;
      return 0;
    default:
      return 0;
    }
}
