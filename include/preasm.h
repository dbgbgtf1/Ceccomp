#ifndef PREASM
#define PREASM

#include <stdio.h>

extern void clear_color (char *clean_line);

extern void pre_asm (FILE *fp, char **origin, char **clean);

#endif
