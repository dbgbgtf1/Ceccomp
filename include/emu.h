#ifndef EMU
#define EMU

#include "main.h"
#include "preasm.h"
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <stdio.h>

typedef struct
{
  uint32_t A;
  uint32_t X;

  uint32_t mem[BPF_MEMWORDS];
} reg_mem;

static bool is_state_true (uint32_t A, uint32_t sym_enum, uint32_t rval);

static bool emu_condition (char *sym_str, reg_mem *reg, seccomp_data *data,
                           char *origin_line);

static void emu_assign_line (line_set *Line, reg_mem *reg, seccomp_data *data);

static uint32_t emu_ret_line (line_set *Line);

static uint32_t emu_if_line (line_set *Line, reg_mem *reg, seccomp_data *data);

static void clear_color (char *origin_line);

static void emu_lines (FILE *fp, seccomp_data *data);

extern void emu (int argc, char *argv[]);

#endif
