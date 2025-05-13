#ifndef ASM
#define ASM

#include "main.h"
#include "preasm.h"
#include <stdbool.h>
#include <stdint.h>

typedef enum
{
  HEXLINE = 0,
  HEXFMT = 1,
  RAW = 2
} print_mode;

extern void assemble (int argc, char *argv[]);

#endif
