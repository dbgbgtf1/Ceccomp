#include "disasm.h"
#include "dump.h"
#include <stdio.h>
#include <string.h>

void
help ()
{
  printf ("Ceccomp: usage [operaion] [args]\n");
  printf ("Example as follows\n");
  printf ("Ceccomp dump program program-args\n");
  printf ("Ceccomp disasm xxx.bpf\n");
}

int
main (const int argc, char *const argv[], const char *const env[])
{
  if (argc < 2)
    help ();
  if (!strcmp (argv[1], "dump"))
    dump (argc, &argv[2]);
  // Ceccomp dump program program-args
  else if (!strcmp (argv[1], "disasm"))
    disasm (argc, &argv[2]);
  // Ceccomp disasm arch xxx.bpf
}

// dump
// emu
// disasm
// asm
