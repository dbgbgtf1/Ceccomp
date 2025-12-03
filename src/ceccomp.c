#include "readsource.h"
#include "scanner.h"
#include "token.h"
#include <stdio.h>

int
main ()
{
  FILE *fp = fopen ("/home/dbgbgtf/Main/work/Ceccomp/test/text/chromium", "r");

  char *source = read_source (fp);
  init_scanner (source);
  token_t token;
  do
    token = scan_token ();
  while (token.type != TOKEN_EOF && token.type != UNKNOWN);
}
