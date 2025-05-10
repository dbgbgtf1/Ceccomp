// this is for separately function testing
#include <stdio.h>
#include <sys/utsname.h>

int main()
{
  struct utsname uname_ptr;
  uname(&uname_ptr);

  printf("machince: %s", uname_ptr.machine);
}
