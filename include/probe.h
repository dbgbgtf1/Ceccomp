#ifndef PROBE
#define PROBE

#include <stdint.h>
#include <stdio.h>

#define ARRAY_SIZE(arr) (sizeof (arr) / sizeof (arr[0]))
#define CMD_LEN 0x100

extern void probe (char *argv[], uint32_t arch_token, FILE *fp);

#endif
