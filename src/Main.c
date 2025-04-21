#include <string.h>
#include "../include/dump.h"
#include "../include/Main.h"

void
strict ()
{
}

int
main (int argc, char *argv[])
{
  if (!strcmp (argv[1], "dump"))
    dump (argv);
}
// dump
// disasm
// asm
