#ifndef PREASM
#define PREASM

#include <stdio.h>

typedef struct
{
  char *clean_line;
  char *origin_line;
} line_set;

extern void pre_clear_color (char *clean_line);

extern void free_line (line_set *Line);

extern void pre_asm (FILE *fp, line_set *Line);

#endif
