#ifndef PROBE
#define PROBE

#include <stdint.h>
#include <stdio.h>

#define ARRAY_SIZE(arr) (sizeof (arr) / sizeof (arr[0]))

extern void probe (char *argv[], FILE *fp);

#endif
