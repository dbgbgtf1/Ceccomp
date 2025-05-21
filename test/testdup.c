#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
global_hide_stdout (int filedup2)
{
  int stdout_backup = dup (fileno (stdout));
  if (stdout_backup == -1)
    perror ("dup");

  if (dup2 (filedup2, fileno (stdout)) == -1)
    perror ("global_start_quiet dup2");

  return stdout_backup;
}

void
global_ret_stdout (int stdout_backup)
{
  if (dup2 (stdout_backup, fileno (stdout)) == -1)
    perror ("global_end_quiet dup2");
  close (stdout_backup);
}

// int
// main ()
// {
//   setbuf (stdout, NULL);
//
//   int filedup2 = open ("/dev/stderr", O_RDWR);
//   int stdout_backup = global_hide_stdout (filedup2);
//   printf ("Yooooo\n");
//   global_ret_stdout (stdout_backup);
//   printf ("what about now\n");
//
//   stdout_backup = global_hide_stdout (filedup2);
//   printf ("Yooooo again\n");
//   global_ret_stdout (stdout_backup);
//   printf ("what about now\n");
// }
