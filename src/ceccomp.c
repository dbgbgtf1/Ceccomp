// this is for unit test
#include "asm.h"
#include "color.h"
#include "config.h"
#include "disasm.h"
#include "emu.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include "parseargs.h"
#include "probe.h"
#include "trace.h"
#include "transfer.h"
#include <argp.h>
#include <assert.h>
#include <libintl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>

static struct utsname uts_name;
static void
init_args (ceccomp_args *args)
{
  uname (&uts_name);

  args->mode = HELP_ABNORMAL;
  args->arch_token = STR2ARCH (uts_name.machine);
  args->read_fp = stdin;
  args->output_fp = stderr;
  args->file_name = NULL;
  args->fmt_mode = HEXLINE;
  args->quiet = false;
  args->syscall_nr = (char *)ARG_INIT_VAL;
  args->sys_args[0] = 0;
  args->sys_args[1] = 0;
  args->sys_args[2] = 0;
  args->sys_args[3] = 0;
  args->sys_args[4] = 0;
  args->sys_args[5] = 0;
  args->ip = 0;
  args->program_idx = ARG_INIT_VAL;
  args->pid = (pid_t)ARG_INIT_VAL;

  char *no_color = getenv ("NO_COLOR");
  if (no_color != NULL && no_color[0] != '\0')
    args->color = NEVER;
  else
    args->color = AUTO;
}

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
init_output ()
{
  setbuf (stdin, NULL);
  setbuf (stdout, NULL);
  setbuf (stderr, NULL);
// passed in Makefile
#ifdef LOCALEDIR
  setlocale (LC_ALL, "");
  bindtextdomain ("ceccomp", LOCALEDIR);
  textdomain ("ceccomp");
#endif
}

__attribute__ ((noreturn)) static void
help (int exit_code)
{
  printf ("%s", CECCOMP_USAGE);
  putchar ('\n');
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

__attribute__ ((noreturn)) static void
version ()
{
  printf (VERSION_FORMAT, CECCOMP_VERSION, CECCOMP_TAG_TIME, CECCOMP_BUILDER);
  exit (0);
}

static void
error_if_arch_not_supported (uint32_t arch_token)
{
  // only if token is converted from uts, it would be -1 here
  if (arch_token == (uint32_t)-1)
    error (SYSTEM_ARCH_NOT_SUPPORTED, uts_name.machine);
}

int
main (int argc, char **argv)
{
  init_output ();

  ceccomp_args args;
  init_args (&args);

  static struct argp argp
      = { options, parse_opt, NULL, NULL, NULL, NULL, NULL };
  argp_parse (&argp, argc, argv, ARGP_IN_ORDER, 0, &args);

  uint32_t program_start_idx = -1;
  if (args.mode == TRACE_PROG_MODE || args.mode == PROBE_MODE)
    {
      if (args.file_name)
        {
          args.output_fp = fopen (args.file_name, "w+");
          free (args.file_name);
          if (args.output_fp == NULL)
            error ("%s: %s", UNABLE_OPEN_FILE, args.file_name);
        }
      program_start_idx = args.program_idx;
      set_color (&args, args.output_fp);
    }
  else
    set_color (&args, stdout);

  switch (args.mode)
    {
    case ASM_MODE:
      error_if_arch_not_supported (args.arch_token);
      assemble (args.arch_token, args.read_fp, args.fmt_mode);
      return 0;
    case DISASM_MODE:
      error_if_arch_not_supported (args.arch_token);
      disasm (args.arch_token, args.read_fp);
      return 0;
    case EMU_MODE:
      error_if_arch_not_supported (args.arch_token);
      emulate (&args);
      return 0;
    case PROBE_MODE:
      probe (&argv[program_start_idx], args.output_fp);
      return 0;
    case TRACE_PID_MODE:
      pid_trace (args.pid);
      return 0;
    case TRACE_PROG_MODE:
      program_trace (&argv[program_start_idx], args.output_fp, false);
      return 0;
    case VERSION_MODE:
      version ();
    case HELP_MODE:
      help (0);
    case HELP_ABNORMAL:
      help (1);
    default:
      assert (0);
    }
}
