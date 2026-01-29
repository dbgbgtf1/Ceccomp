#include "disasm.h"
#include "decoder/decoder.h"
#include "decoder/formatter.h"
#include "lexical/parser.h"
#include "main.h"
#include "resolver/render.h"
#include "utils/error.h"
#include "utils/logger.h"
#include "utils/reverse_endian.h"
#include "utils/str_pile.h"
#include "utils/vector.h"
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

filter g_filters[1024];

static uint32_t
read_filters (filter *filters, FILE *from)
{
  uint32_t todo = sizeof (filter) * (1024 + 1);
  uint8_t *ptr = (uint8_t *)filters;
  int fd = fileno (from);
  assert (fd != -1);
  while (todo)
    {
      long rc = read (fd, ptr, todo);
      if (rc == -1)
        error ("read: %s", strerror (errno));
      if (rc == 0)
        break;
      ptr += rc;
      todo -= rc;
    }
  if (!todo)
    error ("%s", M_TOO_LARGE_INPUT);
  uint32_t leftover = (size_t)ptr & 7;
  if (leftover)
    warn (M_INPUT_HAS_LEFTOVER, leftover);
  return (ptr - (uint8_t *)filters) >> 3;
}

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
  prog.len = read_filters (g_filters, fp);
  if (prog.len == 0)
    {
      warn ("%s", M_NO_FILTER);
      return;
    }

  print_prog (scmp_arch, &prog, stdout);
}
