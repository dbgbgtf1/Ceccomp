#ifndef PARSEARGS
#define PARSEARGS

#include <argp.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum
{
  ASM_MODE,
  DISASM_MODE,
  EMU_MODE,
  TRACE_MODE,
  PROBE_MODE,
  HELP_MODE,
  VERSION_MODE,
  HELP_ABNORMAL,
} subcommand;

typedef enum
{
  HEXLINE,
  HEXFMT,
  RA,
} print_mode;

typedef enum
{
  ALWAYS,
  AUTO,
  NEVER,
} color_mode;

typedef struct
{
  uint32_t arch_enum;
  print_mode mode;
  char *text_name;
} asm_args;

typedef struct
{
  uint32_t arch_enum;
  char *raw_name;
} disasm_args;

typedef struct
{
  uint32_t arch_enum;
  bool quiet;
  char *text_name;
  char *sys_name;
  uint64_t args[6];
  uint64_t ip;
} emu_args;

typedef struct
{
  char *output_file;
  char *program;
} probe_args;

typedef struct
{
  char *output_file;
  char *program;
} trace_prog_args;

typedef struct
{
  char *output_file;
  pid_t pid;
} trace_pid_args;

typedef enum
{
  TRACE_PROG,
  TRACE_PID,
} trace_mode;

typedef struct
{
  trace_mode mode;
  union
  {
    trace_prog_args trace_prog_arg;
    trace_pid_args trace_pid_args;
  };
} trace_args;

typedef struct
{
  subcommand cmd;
  color_mode when;
  union
  {
    asm_args asm_arg;
    disasm_args disasm_arg;
    emu_args emu_arg;
    probe_args probe_arg;
    trace_args trace_arg;
  };
} ceccomp_args;

extern error_t parse_opt (int key, char *arg, struct argp_state *state);

#endif
