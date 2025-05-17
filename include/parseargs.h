#ifndef PARSEARGS
#define PARSEARGS

#include <argp.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum
{
  ASM_MODE = 0,
  DISASM_MODE = 1,
  EMU_MODE = 2,
  TRACE_MODE = 3,
  TRACE_PID_MODE = 4,
  TRACE_PROG_MODE = 5,
  PROBE_MODE = 6,
} subcommand;

typedef enum
{
  HEXLINE = 0,
  HEXFMT = 1,
  RAW = 2
} print_mode;

struct ceccomp_args
{
  subcommand mode;

  uint32_t arch_token;
  FILE *output_fp;
  FILE *read_fp;

  print_mode fmt_mode;

  bool quiet;
  uint32_t syscall_nr;
  uint64_t sys_args[6];
  uint64_t ip;

  char *program_start;
  pid_t pid;
};

typedef struct ceccomp_args ceccomp_args;

#define ARG_INIT_VAL (uint64_t)-1

extern void version ();

extern void help ();

extern uint64_t strtoull_check (char *num, int base, char *err);

extern uint32_t get_arg_idx (int argc, char *argv[], char *arg_to_find);

extern error_t parse_opt (int key, char *arg, struct argp_state *state);

#endif
