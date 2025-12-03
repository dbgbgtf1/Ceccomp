#ifndef COLOR
#define COLOR

#include <stdbool.h>
#include <stdio.h>

#define FORMAT "L%04d"
typedef enum
{
  ALWAYS = 0,
  AUTO = 1,
  NEVER = 2
} color_mode;

extern bool color_enable;
extern bool log_color_enable;

extern void set_color (color_mode color, FILE *output);

#define CLR "\x1b[0m"

#define REDCLR "\x1b[31m"
#define GREENCLR "\x1b[32m"
#define YELLOWCLR "\x1b[33m"
#define BLUECLR "\x1b[34m"
#define CYANCLR "\x1b[36m"
#define PURPLECLR "\x1b[95m"
#define LIGHTCLR "\x1b[90m"
#define BRIGHT_YELLOWCLR "\x1b[93m"
#define BRIGHT_BLUECLR "\x1b[94m"
#define BRIGHT_CYANCLR "\x1b[96m"

#define RED(str) ((color_enable) ? (REDCLR str CLR) : str)
#define GREEN(str) ((color_enable) ? (GREENCLR str CLR) : str)
#define YELLOW(str) ((color_enable) ? (YELLOWCLR str CLR) : str)
#define BRIGHT_YELLOW(str) ((color_enable) ? (BRIGHT_YELLOWCLR str CLR) : str)
#define BLUE(str) ((color_enable) ? (BLUECLR str CLR) : str)
#define BRIGHT_BLUE(str) ((color_enable) ? (BRIGHT_BLUECLR str CLR) : str)
#define CYAN(str) ((color_enable) ? (CYANCLR str CLR) : str)
#define BRIGHT_CYAN(str) ((color_enable) ? (BRIGHT_CYANCLR str CLR) : str)
#define PURPLE(str) ((color_enable) ? (PURPLECLR str CLR) : str)
#define LIGHT(str) ((color_enable) ? (LIGHTCLR str CLR) : str)

#endif
