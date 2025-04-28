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

static char *GetLines (FILE *fp);

static void ClearColor (char *Line);

static void ClearSpace (char *Line);

void PreAsm (FILE *fp, line_set *Line);

#endif
