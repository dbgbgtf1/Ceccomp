#ifndef PREASM
#define PREASM

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

bool isEtc (char *Line);

char *RetLines (FILE *fp);

void ClearColor (char *Line);

void ClearSpace (char *Line);

char *PreAsm (FILE *fp);

#endif
