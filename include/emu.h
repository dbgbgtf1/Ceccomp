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

extern void global_ret_stdout (int stdout_backup);

extern int global_hide_stdout (int filedup2);

extern char *emu_lines (FILE *fp, seccomp_data *data);

extern void emulate (ceccomp_args *args);

#endif
