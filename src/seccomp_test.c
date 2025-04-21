#include "../include/parsefilter.h"
#include <linux/filter.h>
#include <errno.h>
#include <fcntl.h>
#include <seccomp.h>
#include <stdlib.h>
#include <unistd.h>

int
main (int argc, const char **argv)
{
  int fd;
  int len;
  struct sock_fprog *prog;
  scmp_filter_ctx ctx;

  fd = open ("raw_bpf", O_RDWR | O_CREAT, S_IRWXU);
  ctx = seccomp_init (SCMP_ACT_ALLOW);
  seccomp_rule_add (ctx, SCMP_ACT_ERRNO(errno), 0x20, 0);
  seccomp_rule_add (ctx, SCMP_ACT_KILL, 0x30, 0);
  seccomp_rule_add (ctx, SCMP_ACT_KILL, 0x40, 0);
  seccomp_rule_add (ctx, SCMP_ACT_KILL, 0x50, 0);
  seccomp_export_bpf (ctx, fd);

  close (fd);
  fd = open ("raw_bpf", O_RDONLY);

  prog = (fprog*)malloc(0x10);
  prog->filter = (filter*)malloc (0x1000);

  len = read (fd, prog->filter, 0x1000);
  prog->len = len / sizeof (filter);

  ParseFilter (0xc000003e, prog);
  close (fd);

  fd = open ("rule", O_RDWR | O_CREAT, S_IRWXU);
  seccomp_export_pfc (ctx, fd);
  return 0;
}
