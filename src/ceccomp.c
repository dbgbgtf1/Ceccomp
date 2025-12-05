#include "debug_method.h"
#include "hash.h"
#include "parser.h"
#include "readsource.h"
#include "scanner.h"
#include <stdio.h>

int
main (int argc, char *argv[])
{
  FILE *fp = fopen (argv[1], "r");

  char *source = read_source (fp);
  init_scanner (source);
  init_table ();

  state_ment_t state_ment;
  init_parser ();
  do
    {
      parse_line (&state_ment);
      print_statement (&state_ment);
    }
  while (state_ment.type != EOF_LINE);

  free_table ();
}
