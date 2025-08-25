#include "color.h"
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

bool color_enable = true;

void
disable_color ()
{
  color_enable = false;
}

void
enable_color ()
{
  color_enable = true;
}

void
set_color (ceccomp_args *args, FILE *output)
{
  if (args->color == ALWAYS)
    enable_color ();
  else if (args->color == NEVER)
    disable_color ();

  else if (args->color == AUTO)
    {
      if (isatty (fileno (output)))
        enable_color ();
      else
        disable_color ();
    }
}
