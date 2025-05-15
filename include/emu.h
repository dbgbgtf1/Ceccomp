#ifndef EMU
#define EMU

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include "main.h"

typedef struct
{
  uint32_t A;
  uint32_t X;

  uint32_t mem[BPF_MEMWORDS];
} reg_mem;

extern int start_quiet ();

extern void end_quiet (int stdout_backup);

extern char *emu_lines (FILE *fp, seccomp_data *data);

extern void emu (int argc, char *argv[]);

#endif
