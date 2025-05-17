#include "disasm.h"
#include "main.h"
#include "parsefilter.h"
#include <stdint.h>

void
disasm (uint32_t arch_token, FILE *read_fp)
{
  filter buf[1024];
  fprog prog;
  prog.filter = buf;

  prog.len = fread (buf, sizeof (filter), 1024, read_fp);

  parse_filter (arch_token, &prog, stdout);
}
