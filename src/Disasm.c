#include "disasm.h"
#include "Main.h"
#include "error.h"
#include "parsefilter.h"
#include "transfer.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void
disasm (const int argc, char *const argv[])
{
  if (argc != 4)
    PEXIT ("%s", "Ceccomp disasm arch xxx.bpf");

  uint32_t arch = STR2ARCH (argv[0]);
  if (arch == 0)
    PEXIT ("invalid arch: %s\nsupport arch: X86 X86_64 X32 ARM AARCH64 MIPS "
           "MIPSEL MIPSEL64 MIPSEL64N32 PARISC PARISC64 PPC PPC64 PPC64LE "
           "S390 S390X RISCV64\n",
           argv[0]);

  int fd = open (argv[1], O_RDONLY);
  if (fd == -1)
    PEXIT ("unable to open %s", argv[1]);

  filter *const bpf = malloc (0x1000);
  int len = read (fd, bpf, 0x1000);
  
  fprog *const prog = malloc (sizeof (fprog));
  prog->len = (len / sizeof(filter));
  prog->filter = bpf;

  ParseFilter(arch, prog);
}
