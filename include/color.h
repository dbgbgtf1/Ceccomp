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

#define RED(str) ((color_enable) ? (REDCLR str CLR) : str)
#define GREEN(str) ((color_enable) ? (GREENCLR str CLR) : str)
#define YELLOW(str) ((color_enable) ? (YELLOWCLR str CLR) : str)
#define BLUE(str) ((color_enable) ? (BLUECLR str CLR) : str)
#define CYAN(str) ((color_enable) ? (CYANCLR str CLR) : str)
#define PURPLE(str) ((color_enable) ? (PURPLECLR str CLR) : str)
#define LIGHT(str) ((color_enable) ? (LIGHTCLR str CLR) : str)

#define REG_A YELLOW ("$A")
#define REG_X YELLOW ("$X")
#define MEM_K YELLOW ("$mem[0x%1x]")
#define YELLOW_S YELLOW ("%s")
#define BLUE_S BLUE ("%s")

#define CYAN_S CYAN ("%s")
#define CYAN_H CYAN ("0x%x")

#define CYAN_LS CYAN ("%.*s")

#endif
