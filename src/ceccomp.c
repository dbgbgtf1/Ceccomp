#include "asm.h"
#include "disasm.h"
#include "emu.h"
#include "main.h"
#include "parseargs.h"
#include "trace.h"
#include "transfer.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>

void
help ()
{
  printf ("ceccomp: usage [subcommand] [args]\n");
  printf ("\n");
  printf ("%s\n", ASM_HINT);
  printf ("%s\n", DISASM_HINT);
  printf ("%s\n", TRACE_HINT);
  printf ("%s\n", EMU_HINT);
  printf ("%s\n", HELP_HINT);
  printf ("%s\n", VERSION);

  printf ("\n%s\n", OPTION_HINT);
  exit (0);
}

void
version ()
{
  printf ("ceccomp 1.0\n");
  exit (0);
}

char **
set_local_arch (int *argc, char *argv[])
{
  char *arch_str = parse_option ((*argc - 2), &argv[2], "arch");
  if (arch_str != NULL)
    {
      uint32_t token = STR2ARCH (arch_str);
      if (token != -1)
        return argv;
    }

  struct utsname uts_name;
  uname (&uts_name);

  char **argv_cpy = malloc (sizeof (char *) * (*argc + 1));
  argv_cpy[0] = argv[0];
  argv_cpy[1] = argv[1];
  argv_cpy[2] = malloc (strlen (uts_name.machine) + strlen ("--arch="));

  strcpy (argv_cpy[2], "--arch=");
  strcpy (argv_cpy[2] + strlen ("--arch="), uts_name.machine);

  memcpy (&argv_cpy[3], &argv[2], sizeof (char *) * (*argc - 2));

  *argc += 1;
  return argv_cpy;
}

int
main (int argc, char *argv[], char *env[])
{
  if (argc < 2)
    {
      help ();
      return 0;
    }

  if (!strcmp (argv[1], "version"))
    {
      version ();
      return 0;
    }

  if (!strcmp (argv[1], "trace"))
    {
      trace (argc - 2, &argv[2]);
      return 0;
    }

  argv = set_local_arch (&argc, argv);
  // make sure argv have --arch now;

  if (!strcmp (argv[1], "asm"))
    assemble (argc - 2, &argv[2]);

  else if (!strcmp (argv[1], "disasm"))
    disasm (argc - 2, &argv[2]);

  else if (!strcmp (argv[1], "emu"))
    emu (argc - 2, &argv[2]);

  else
    help ();
}
