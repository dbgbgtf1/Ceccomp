#ifndef PREASM
#define PREASM

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct
{
  char *clean_line;
  char *origin_line;
}line_set;

bool isEtc (char *Line);

char *RetLines (FILE *fp);

void ClearColor (char *Line);

void ClearSpace (char *Line);

void PreAsm (FILE *fp, line_set *Line);

#endif
