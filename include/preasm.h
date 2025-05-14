#ifndef PREASM
#define PREASM

#include <stdio.h>

typedef struct
{
  char *clean_line;
  char *origin_line;
} line_set;

extern void safe_strcpy (char *dest, char *src);

extern void pre_asm (FILE *fp, line_set *Line);

#endif
