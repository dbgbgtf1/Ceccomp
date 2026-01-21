#ifndef READ_SOURCE_H
#define READ_SOURCE_H

#include <stdio.h>

// read file at once, the pointer is all fixed
extern unsigned init_source (FILE *read_fp);

// return NULL to indicate EOF
extern char *next_line (void);

extern void free_source (void);

#endif
