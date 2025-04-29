#include "main.h"
#include "asm.h"
#include "disasm.h"
#include "dump.h"
#include "emu.h"
#include <stdio.h>
#include <string.h>

void
help ()
{
  printf ("ceccomp: usage [operaion] [args]\n");
  printf ("Example as follows\n");
  printf("%s\n", ASM_HINT);
  printf("%s\n", DISASM_HINT);
  printf("%s\n", DUMP_HINT);
  printf("%s\n", EMU_HINT);
}

int
main (int argc, char *argv[], char *env[])
{
  if (argc < 2)
    help ();

  if (!strcmp (argv[1], "--asm"))
    assemble (argc - 2, &argv[2]);

  else if (!strcmp (argv[1], "--disasm"))
    disasm (argc - 2, &argv[2]);

  else if (!strcmp (argv[1], "--dump"))
    dump (argc - 2, &argv[2]);

  else if (!strcmp (argv[1], "--emu"))
    emu (argc - 2, &argv[2]);

  else
    help();
}

// dump
// emu
// disasm
// asm
