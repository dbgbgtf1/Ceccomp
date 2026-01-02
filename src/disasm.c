#include "disasm.h"
#include "color.h"
#include "decoder.h"
#include "formatter.h"
#include "main.h"
#include "parser.h"
#include "render.h"
#include "vector.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

filter filters[1024];

void
disasm (FILE *fp, uint32_t scmp_arch)
{
  fprog prog;
  prog.filter = filters;
  prog.len = fread (filters, sizeof (filter), 1024, fp);

  vector_t v_code;
  vector_t v_ptr;
  init_vector (&v_code, sizeof (statement_t));
  init_vector (&v_code, sizeof (char *));
  render (&v_code, &v_ptr, scmp_arch);
  decode_filters (&prog, &v_code);
  puts (LIGHT ("#Label  CODE  JT   JF      K"));
  puts (LIGHT ("#---------------------------------"));

  for (uint32_t i = 0; i < v_code.count; i++)
    {
      filter f = filters[i];
      printf (" " DEFAULT_LABEL ": 0x%02x 0x%02x 0x%02x 0x%08x ", i, f.code,
              f.jt, f.jf, f.k);
      print_statement (get_vector (&v_code, i));
    }

  puts (LIGHT ("#---------------------------------"));
  for (uint32_t i = 0; i < v_ptr.count; i++)
    free (*((char **)get_vector (&v_ptr, i)));

  free_vector (&v_code);
}
