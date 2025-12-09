// this is for separately function testing
#include "debug_method.h"
#include "hash.h"
#include "parser.h"
#include "read_source.h"
#include "scanner.h"
#include <stdio.h>

int
main (int argc, char *argv[])
{
  FILE *fp = fopen (argv[1], "r");
  init_source (fp);
  init_scanner (next_line ());
  init_parser ();
  init_table ();

  statement_t statement;
  do
    {
      parse_line (&statement);
      print_statement (&statement);
    }
  while (statement.type != EOF_LINE);

  free_table ();
  free_source ();
}
