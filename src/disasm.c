#include "disasm.h"
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

  vector_t v;
  vector_t v_ptr;

  init_vector (&v, sizeof (statement_t));
  init_vector (&v_ptr, sizeof (char *));
  decode_filters (&prog, &v);
  render (&v, &v_ptr, scmp_arch);
  print_as_comment ("Label  CODE  JT   JF      K");
  print_as_comment ("---------------------------------");

  for (uint32_t i = 1; i < v.count; i++)
    {
      filter f = filters[i];
      printf (" " DEFAULT_LABEL ": 0x%02x 0x%02x 0x%02x 0x%08x ", i, f.code,
              f.jt, f.jf, f.k);
      print_statement (get_vector (&v, i));
    }

  print_as_comment ("---------------------------------");

  for (uint32_t i = 0; i < v_ptr.count; i++)
    free (*((char **)get_vector (&v_ptr, i)));
  free_vector (&v);
  free_vector (&v_ptr);
}
