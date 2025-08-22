#ifndef EMU
#define EMU

#include "main.h"
#include "parseargs.h"

typedef struct
{
  uint32_t A;
  uint32_t X;

  uint32_t mem[BPF_MEMWORDS];
} reg_mem;

extern char *emu_lines (bool quiet, FILE *read_fp, seccomp_data *data);

extern void emulate (ceccomp_args *args);

#endif
