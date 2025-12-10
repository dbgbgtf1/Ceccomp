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
  FILE *fp = fopen (argv[1], "r");
  init_source (fp);
  init_scanner (next_line ());
  init_parser ();
  init_table ();

  vector_t v;
  init_vector (&v, sizeof (statement_t));
  statement_t statement;
  do
    {
      parse_line (&statement);
      push_vector (&v, &statement);
    }
  while (statement.type != EOF_LINE);

  uname (&uts);
  uint32_t arch = str_to_scmp_arch (uts.machine);
  if (arch == (uint32_t)-1)
    error ("arch is invalid: %s", uts.machine);
  resolver (&v, arch);

  statement_t *copy = get_vector (&v, 0);
  for (uint32_t i = 0; copy->type != EOF_LINE; i++)
    {
      print_statement (copy);
      copy = get_vector (&v, i);
    }

  free_table ();
  free_source ();
}
