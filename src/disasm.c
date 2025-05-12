#include "disasm.h"
#include "error.h"
#include "main.h"
#include "parseargs.h"
#include "parsefilter.h"
#include "transfer.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void
disasm (int argc, char *argv[])
{
  char *arch_str = parse_option (argc, argv, "arch");
  uint32_t arch = STR2ARCH (arch_str);
  if (arch == -1)
    PEXIT (INVALID_ARCH ": %s\n" SUPPORT_ARCH, arch_str);

  char *filename = get_arg (argc, argv);

  int fd = open (filename, O_RDONLY);
  if (fd == -1)
    PEXIT (UNABLE_OPEN_FILE ": %s", filename);

  fprog prog;
  filter buf[0x100];
  prog.filter = buf;

  prog.len = (read (fd, buf, 0x100 * sizeof (filter))) / sizeof (filter);

  parse_filter (arch, &prog);
}
