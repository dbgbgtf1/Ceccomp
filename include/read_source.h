#ifndef READ_SOURCE
#define READ_SOURCE

#include <stdio.h>

extern char *init_source (FILE *read_fp);

// return NULL to indicate EOF
extern char *next_line (void);

extern void free_source (void);

#endif
