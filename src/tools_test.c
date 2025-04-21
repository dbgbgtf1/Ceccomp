#include "../include/parsefilter.h"
#include "../include/Main.h"
#include "../include/transfer.h"
#include <linux/filter.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

// usage: ./test arch ./bpf/xxxx.bpf
int main(int argc, const char** argv)
{
  int fd = open(argv[2], O_RDONLY);
  fprog * prog = malloc(sizeof(fprog));
  prog->filter = malloc(0x1000);
  int len = read(fd, prog->filter, 0x1000);
  prog->len = len / sizeof(filter);
  
  ParseFilter(STR2ARCH(argv[1]), prog);
}
