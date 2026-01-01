#include "disasm.h"
#include "color.h"
#include "decoder.h"
#include "main.h"
#include "parser.h"
#include "formatter.h"
#include "vector.h"
#include <stdint.h>
#include <stdio.h>

filter filters[1024];

void
disasm (FILE *fp, uint32_t scmp_arch)
{
  fprog prog;
  prog.filter = filters;
  prog.len = fread (filters, sizeof (filter), 1024, fp);

  vector_t v;
  init_vector (&v, sizeof (statement_t));
  decode_filters (&prog, &v);
  puts (LIGHT ("#Label  CODE  JT   JF      K"));
  puts (LIGHT ("#---------------------------------"));

  for (uint32_t i = 0; i < v.count; i++)
    {
      filter f = filters[i];
      printf (" " DEFAULT_LABEL ": 0x%02x 0x%02x 0x%02x 0x%08x ", i, f.code,
              f.jt, f.jf, f.k);
      print_statement (get_vector (&v, i));
    }

  puts (LIGHT ("#---------------------------------"));
  free_vector (&v);
}
