#include "color.h"
#include <stdbool.h>

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
