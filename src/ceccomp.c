#include "asm.h"
#include "disasm.h"
#include "emu.h"
#include "error.h"
#include "main.h"
#include "parseargs.h"
#include "trace.h"
#include "transfer.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/utsname.h>

#define CECCOMP_VERSION "ceccomp 1.3"

void
help ()
{
  printf ("usage: ceccomp [subcommand] [args] [options]\n");
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
  printf (CECCOMP_VERSION "\n");
  exit (0);
}

char **
set_local_arch (int *argc, char *argv[])
{

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
  setbuf (stdout, NULL);

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

  char *arch_str = parse_option_mode ((argc - 2), &argv[2], "arch");
  bool need_to_free_argv = false;
  if (arch_str != NULL)
    {
      uint32_t token = STR2ARCH (arch_str);
      if (token == -1)
        PEXIT (INVALID_ARCH ": %s\n" SUPPORT_ARCH, arch_str);
    }
  else
    {
      argv = set_local_arch (&argc, argv);
      need_to_free_argv = true;
    }
  // make sure argv have --arch now;

  if (!strcmp (argv[1], "asm"))
    assemble (argc - 2, &argv[2]);

  else if (!strcmp (argv[1], "disasm"))
    disasm (argc - 2, &argv[2]);

  else if (!strcmp (argv[1], "emu"))
    emu (argc - 2, &argv[2]);

  else if (!strcmp (argv[1], "trace"))
    trace (argc - 2, &argv[2]);

  else
    help ();

  if (!need_to_free_argv)
    return 0;

  free (argv[2]);
  free (argv);
}
