#include "readsource.h"
#include "scanner.h"
#include "token.h"
#include <stdio.h>

int
main (int argc, char *argv[])
{
  FILE *fp = fopen (argv[1], "r");

  char *source = read_source (fp);
  init_scanner (source);
  token_t token;
  do
    token = scan_token ();
  while (token.type != TOKEN_EOF && token.type != UNKNOWN);
}
