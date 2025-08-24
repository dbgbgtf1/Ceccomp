// this is for unit test
#include "asm.h"
#include "color.h"
#include "disasm.h"
#include "emu.h"
#include "log/logger.h"
#include "parseargs.h"
#include "probe.h"
#include "trace.h"
#include "transfer.h"
#include <argp.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>

void
init (ceccomp_args *args)
{
  struct utsname uts_name;
  uname (&uts_name);

  args->mode = HELP_ABNORMAL;
  args->arch_token = STR2ARCH (uts_name.machine);
  args->output_fp = stderr;
  args->read_fp = stdin;
  args->fmt_mode = HEXLINE;
  args->quiet = false;
  args->color = true;
  args->syscall_nr = (char *)ARG_INIT_VAL;
  args->sys_args[0] = ARG_INIT_VAL;
  args->sys_args[1] = ARG_INIT_VAL;
  args->sys_args[2] = ARG_INIT_VAL;
  args->sys_args[3] = ARG_INIT_VAL;
  args->sys_args[4] = ARG_INIT_VAL;
  args->sys_args[5] = ARG_INIT_VAL;
  args->program_idx = ARG_INIT_VAL;
  args->pid = (pid_t)ARG_INIT_VAL;
}

static struct argp_option options[] = {
  { "quiet", 'q', NULL, 0, NULL, 0 },
  { "no-color", 'c', NULL, 0, NULL, 0 },
  { "output", 'o', "OUTPUT", 0, NULL, 0 },
  { "arch", 'a', "ARCH", 0, NULL, 0 },
  { "pid", 'p', "PID", 0, NULL, 0 },
  { "fmt", 'f', "FMT", 0, NULL, 0 },
  { "help", 'h', NULL, 0, NULL, 0 },
  { "usage", 'u', NULL, 0, NULL, 0 },
};

int
main (int argc, char **argv)
{
  setbuf (stdin, NULL);
  setbuf (stdout, NULL);
  setbuf (stderr, NULL);

  ceccomp_args args;

  init (&args);
  static struct argp argp
      = { options, parse_opt, NULL, NULL, NULL, NULL, NULL };
  argp_parse (&argp, argc, argv, ARGP_IN_ORDER, 0, &args);

  uint32_t program_start_idx = -1;
  if (args.mode == TRACE_PROG_MODE || args.mode == PROBE_MODE)
    program_start_idx = args.program_idx;

  if (args.color)
    disable_color ();

  switch (args.mode)
    {
    case ASM_MODE:
      assemble (args.arch_token, args.read_fp, args.fmt_mode);
      return 0;
    case DISASM_MODE:
      disasm (args.arch_token, args.read_fp);
      return 0;
    case EMU_MODE:
      emulate (&args);
      return 0;
    case PROBE_MODE:
      probe (&argv[program_start_idx], args.arch_token, args.output_fp);
      return 0;
    case TRACE_PID_MODE:
      pid_trace (args.pid, args.arch_token);
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
