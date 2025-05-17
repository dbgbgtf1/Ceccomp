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

extern int start_quiet ();

extern void end_quiet (int stdout_backup);

extern char *emu_lines (FILE *fp, seccomp_data *data);

extern void emulate (ceccomp_args *args);

#endif
