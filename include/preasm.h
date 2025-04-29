#ifndef PREASM
#define PREASM

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct
{
  char *clean_line;
  char *origin_line;
} line_set;

static bool is_etc (char *origin_line);

static char *pre_get_lines (FILE *fp);

static void pre_clear_color (char *clean_line);

static void pre_clear_space (char *clean_line);

extern void pre_asm (FILE *fp, line_set *Line);

#endif
