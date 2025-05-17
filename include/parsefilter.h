#ifndef PARSEFILTER
#define PARSEFILTER

#include "main.h"
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

  void parse_filter (uint32_t arch, fprog *prog, FILE* output_fileptr);

#ifdef __cplusplus
}
#endif

#endif
