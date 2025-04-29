#include "disasm.h"
#include "error.h"
#include "main.h"
#include "parsefilter.h"
#include "transfer.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void
disasm (int argc, char *argv[])
{
  if (argc < 2)
    PEXIT ("%s\n%s\n", NOT_ENOUGH_ARGS, DISASM_HINT);

  uint32_t arch = STR2ARCH (argv[0]);
  if (arch == -1)
    PEXIT("%s\n%s\n", INVALID_ARCH, SUPPORT_ARCH);

  int fd = open (argv[1], O_RDONLY);
  if (fd == -1)
    PEXIT ("unable to open %s", argv[1]);

  filter *bpf = malloc (0x1000);
  int len = read (fd, bpf, 0x1000);

  fprog *prog = malloc (sizeof (fprog));
  prog->len = (len / sizeof (filter));
  prog->filter = bpf;

  parse_filter (arch, prog);
}
