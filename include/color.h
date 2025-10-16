#ifndef COLOR
#define COLOR

#include "parseargs.h"
#include <stdbool.h>

#define FORMAT "%04d"

extern bool color_enable;
extern bool log_color_enable;

extern void set_color (ceccomp_args *args, FILE *output);

#define CLR "\e[0m"

#define REDCLR "\e[31m"
#define GREENCLR "\e[32m"
#define YELLOWCLR "\e[33m"
#define BLUECLR "\e[34m"
#define CYANCLR "\e[36m"
#define PURPLECLR "\e[95m"
#define LIGHTCLR "\e[90m"
#define BRIGHT_YELLOWCLR "\e[93m"
#define BRIGHT_BLUECLR "\e[94m"
#define BRIGHT_CYANCLR "\e[96m"

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
