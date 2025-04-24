#ifndef EMU
#define EMU

#include "Main.h"
#include <stdint.h>

typedef struct
{
  uint32_t A;
  uint32_t X;

  uint32_t mem[BPF_MEMWORDS];
} reg_mem;

void emu (int argc, char *argv[]);

#endif
