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
  printf ("Ceccomp: usage [operaion] [args]\n");
  printf ("Example as follows\n");
  printf ("Ceccomp dump program program-args\n");
  printf ("Ceccomp disasm xxx.bpf\n");
  printf ("Ceccomp emu text arch nr [ argv[0] - argv[5] ] (default as 0)");
  printf ("Ceccomp asm arch asmcodefile\n");
}

int
main (int argc, char *argv[], char *env[])
{
  if (argc < 2)
    help ();

  if (!strcmp (argv[1], "dump"))
    dump (argc - 2, &argv[2]);
  // Ceccomp dump program [ program-args ]

  else if (!strcmp (argv[1], "emu"))
    emu (argc - 2, &argv[2]);
  // Ceccomp emu text arch nr [ argv[0] - argv[5] ] (default as 0)

  else if (!strcmp (argv[1], "disasm"))
    disasm (argc - 2, &argv[2]);
  // Ceccomp disasm arch xxx.bpf

  else if (!strcmp (argv[1], "asm"))
    assemble (argc - 2, &argv[2]);
  // Ceccomp asm arch asmcodefile
}

// dump
// emu
// disasm
// asm
