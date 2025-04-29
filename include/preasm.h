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

static bool isEtc (char *Line);

static char *PreGetLines (FILE *fp);

static void PreClearColor (char *Line);

static void PreClearSpace (char *Line);

void PreAsm (FILE *fp, line_set *Line);

#endif
