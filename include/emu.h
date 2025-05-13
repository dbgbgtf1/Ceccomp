#ifndef EMU
#define EMU

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>

typedef struct
{
  uint32_t A;
  uint32_t X;

  uint32_t mem[BPF_MEMWORDS];
} reg_mem;

extern void emu (int argc, char *argv[]);

#endif
