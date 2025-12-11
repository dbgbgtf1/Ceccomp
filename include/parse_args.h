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
} subcommand_t;

typedef enum
{
  HEXLINE,
  HEXFMT,
  RAW,
} print_mode_t;

typedef enum
{
  ALWAYS,
  AUTO,
  NEVER,
} color_mode_t;

typedef struct
{
  uint32_t arch_enum;
  print_mode_t mode;
  FILE *text_file;
} asm_arg_t;

typedef struct
{
  uint32_t arch_enum;
  FILE *raw_file;
} disasm_arg_t;

typedef struct
{
  uint32_t arch_enum;
  bool quiet;
  FILE *text_file;
  char *sys_name;
  uint64_t args[6];
  uint64_t ip;
} emu_arg_t;

typedef struct
{
  FILE *output_file;
  uint32_t prog_idx;
} probe_arg_t;

typedef enum
{
  UNDECIDED,
  TRACE_PROG,
  TRACE_PID,
} trace_mode_t;

typedef struct
{
  trace_mode_t mode;
  FILE *output_file;
  uint32_t prog_idx;
  pid_t pid;
} trace_arg_t;

typedef struct
{
  subcommand_t cmd;
  color_mode_t when;

  asm_arg_t *asm_arg;
  disasm_arg_t *disasm_arg;
  emu_arg_t *emu_arg;
  probe_arg_t *probe_arg;
  trace_arg_t *trace_arg;
} ceccomp_arg_t;

extern error_t parse_opt (int key, char *arg, struct argp_state *state);

#endif
