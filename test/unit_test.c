// this is for separately function testing
#include "arch_trans.h"
#include "debug_method.h"
#include "hash.h"
#include "log/logger.h"
#include "parser.h"
#include "read_source.h"
#include "resolver.h"
#include "scanner.h"
#include "vector.h"
#include <stdint.h>
#include <stdio.h>
#include <sys/utsname.h>

static struct utsname uts;

int
main (int argc, char *argv[])
{
  uname (&uts);
  uint32_t arch = str_to_scmp_arch (uts.machine);
  if (arch == (uint32_t)-1)
    error ("arch is invalid: %s", uts.machine);

  FILE *fp = fopen (argv[1], "r");
  init_source (fp);
  init_scanner (next_line ());
  init_parser (arch);
  init_table ();

  vector_t v;
  init_vector (&v, sizeof (statement_t));
  statement_t statement;
  do
    {
      parse_line (&statement);
      if (statement.type != EMPTY_LINE)
        push_vector (&v, &statement);
    }
  while (statement.type != EOF_LINE);
  // EOF_LINE is in get_vector (&v, v.count -1)

  resolver (&v);

  for (uint32_t i = 0; i < v.count - 1; i++)
    print_statement (get_vector (&v, i));

  free_table ();
  free_source ();
  free_vector (&v);
}
