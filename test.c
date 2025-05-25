#include <seccomp.h>
#include <stdio.h>

int main()
{
  int a = seccomp_syscall_resolve_name_arch(SCMP_ARCH_X32, "read");
  printf ("%#x\n", a);
}
