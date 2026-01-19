#include "color.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

bool color_enable = true;
bool log_color_enable = true;

void
set_color (color_mode_t color, FILE *output)
{
  if (color == ALWAYS)
    {
      color_enable = true;
      log_color_enable = true;
    }
  else if (color == NEVER)
    {
      color_enable = false;
      log_color_enable = false;
    }

  else if (color == AUTO)
    {
      if (isatty (fileno (output)))
        color_enable = true;
      else
        color_enable = false;

      if (isatty (STDERR_FILENO))
        log_color_enable = true;
      else
        log_color_enable = false;
    }
}

static bool enable_stack[0x10];
// 0x10 is definitely enough;
static uint32_t enable_sp = 0;

void
push_color (bool enable)
{
  enable_stack[enable_sp++] = color_enable;
  color_enable = enable;
}

void
pop_color (void)
{
  color_enable = enable_stack[--enable_sp];
}
