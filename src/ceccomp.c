#include "debug_method.h"
#include "hash.h"
#include "parse_args.h"
#include "parser.h"
#include "readsource.h"
#include "scanner.h"
#include "resolver.h"
#include "vector.h"
#include <stdio.h>

int
main (int argc, char *argv[])
{
  FILE *fp;
  char *source;
  state_ment_t state_ment;
  vector_t vector;

  fp = fopen (argv[1], "r");
  source = read_source (fp);
  init_scanner (source);
  init_table ();
  init_vector (&vector, sizeof (state_ment_t));
  init_parser ();

  do
    {
      parse_line (&state_ment);
      print_statement (&state_ment);
      push_vector (&vector, &state_ment);
    }
  while (state_ment.type != EOF_LINE);

  resolver (&vector);

  free_vector (&vector);
  free_table ();
}
