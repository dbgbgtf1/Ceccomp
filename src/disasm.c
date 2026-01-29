#include "disasm.h"
#include "decoder/decoder.h"
#include "decoder/formatter.h"
#include "lexical/parser.h"
#include "main.h"
#include "resolver/render.h"
#include "utils/reverse_endian.h"
#include "utils/str_pile.h"
#include "utils/vector.h"
#include <stdint.h>
#include <stdio.h>

filter g_filters[1024];

void
print_prog (uint32_t scmp_arch, fprog *prog, FILE *output_fp)
{
  if (need_reverse_endian (scmp_arch))
    for (uint32_t i = 0; i < prog->len; i++)
      reverse_endian (&prog->filter[i]);

  vector_t v;

  // str pile for syscall names
  init_pile (prog->len * 40 /* statistical choice */);
  init_vector (&v, sizeof (statement_t), prog->len + 1);
  // check_prog in decode_filters might decect some errors
  // render might mem overflow, so skip render
  if (!decode_filters (prog, &v))
    render (&v, scmp_arch);
  print_as_comment (output_fp, "Label  CODE  JT   JF      K");
  print_as_comment (output_fp, "---------------------------------");

  filter *filters = prog->filter; // give compiler some hint
  for (uint32_t i = 1; i < v.count; i++)
    {
      filter f = filters[i - 1];
      fprintf (output_fp, " " DEFAULT_LABEL ": 0x%02x 0x%02x 0x%02x 0x%08x ",
               i, f.code, f.jt, f.jf, f.k);
      print_statement (output_fp, get_vector (&v, i));
    }

  print_as_comment (output_fp, "---------------------------------");

  free_vector (&v);
  free_pile ();
}

void
disasm (FILE *fp, uint32_t scmp_arch)
{
  fprog prog;
  prog.filter = g_filters;
  prog.len = fread (g_filters, sizeof (filter), 1024, fp);

  print_prog (scmp_arch, &prog, stdout);
}
