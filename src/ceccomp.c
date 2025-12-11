#include "arch_trans.h"
#include "parse_args.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

static struct utsname uts;

static asm_arg_t asm_arg;
static disasm_arg_t disasm_arg;
static emu_arg_t emu_arg;
static probe_arg_t probe_arg;
static trace_arg_t trace_arg;

static ceccomp_arg_t args = { .cmd = HELP_ABNORMAL,
                              .asm_arg = &asm_arg,
                              .disasm_arg = &disasm_arg,
                              .emu_arg = &emu_arg,
                              .probe_arg = &probe_arg,
                              .trace_arg = &trace_arg };

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
init_args (ceccomp_arg_t *args)
{
  uname (&uts);
  uint32_t scmp_arch = str_to_scmp_arch (uts.machine);
  args->asm_arg->arch_enum = scmp_arch;
  args->asm_arg->mode = HEXLINE;
  args->asm_arg->text_file = stdin;

  args->disasm_arg->arch_enum = scmp_arch;
  args->disasm_arg->raw_file = stdin;

  args->emu_arg->arch_enum = scmp_arch;
  args->emu_arg->text_file = stdin;
  for (uint32_t i = 0; i <= 5; i++)
    args->emu_arg->args[i] = 0;
  args->emu_arg->ip = 0;
  args->emu_arg->quiet = false;
  args->emu_arg->sys_name = NULL;

  args->probe_arg->output_file = stderr;
  args->probe_arg->prog_idx = 0;

  args->trace_arg->mode = UNDECIDED;
  args->trace_arg->output_file = stderr;
  args->trace_arg->pid = 0;
  args->trace_arg->prog_idx = 0;

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

  switch (args.cmd)
    {
    case ASM_MODE:
      printf ("ASM_MODE\n");
      printf ("arch: 0x%x", args.asm_arg->arch_enum);
      printf (", fmt: %d", args.asm_arg->mode);
      printf (", text: %p\n", args.asm_arg->text_file);
      break;
    case DISASM_MODE:
      printf ("DISASM_MODE\n");
      printf ("arch: 0x%x", args.disasm_arg->arch_enum);
      printf (", raw: %p\n", args.disasm_arg->raw_file);
      break;
    case EMU_MODE:
      printf ("EMU_MODE\n");
      printf ("arch: 0x%x,", args.emu_arg->arch_enum);
      printf (", quiet: %s", args.emu_arg->quiet ? "true" : "false");
      printf (", text: %p,", args.emu_arg->text_file);
      printf (", sys_name: %s", args.emu_arg->sys_name);
      for (int i = 0; i <= 5; i++)
        printf (", args[%d]: %lu", i, args.emu_arg->args[i]);
      printf (", ip: %lu\n", args.emu_arg->ip);
      break;
    case TRACE_MODE:
      printf ("TRACE_MODE\n");
      if (args.trace_arg->mode == TRACE_PID)
        {
          printf ("pid: %d\n", args.trace_arg->pid);
          break;
        }
      for (int i = args.trace_arg->prog_idx; i < argc; i++)
        printf (" %s", argv[i]);
      printf (", output_file: %p\n", args.trace_arg->output_file);
      break;
    case PROBE_MODE:
      printf ("PROBE_MODE\n");
      for (int i = args.probe_arg->prog_idx; i < argc; i++)
        printf ("%s ", argv[i]);
      printf ("\noutput_file: %p\n", args.probe_arg->output_file);
      break;
    case HELP_MODE:
      printf ("HELP_MODE\n");
      break;
    case VERSION_MODE:
      printf ("VERSION_MODE\n");
      break;
    case HELP_ABNORMAL:
      printf ("HELP_ABNORMAL\n");
      break;
    }
  printf ("color: %d\n", args.when);
}
