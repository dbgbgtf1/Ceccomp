#ifndef COLOR
#define COLOR

#include <stdbool.h>

#define FORMAT "%04d"

extern bool color_enable;

extern void disable_color ();

extern void enable_color ();

#define CLR "\e[0m"

#define REDCLR "\e[31m"
#define GREENCLR "\e[32m"
#define YELLOWCLR "\e[33m"
#define CYANCLR "\e[36m"
#define PURPLECLR "\e[95m"
#define LIGHTCLR "\e[90m"

#define RED(str) ((color_enable) ? str : (REDCLR str CLR))
#define GREEN(str) ((color_enable) ? str : (GREENCLR str CLR))
#define YELLOW(str) ((color_enable) ? str : (YELLOWCLR str CLR))
#define CYAN(str) ((color_enable) ? str : (CYANCLR str CLR))
#define PURPLE(str) ((color_enable) ? str : (PURPLECLR str CLR))
#define LIGHT(str) ((color_enable) ? str : (LIGHTCLR str CLR))

#define CYAN_A CYAN ("$A")
#define CYAN_X CYAN ("$X")
#define CYAN_S CYAN ("%s")
#define CYAN_H CYAN ("0x%x")
#define CYAN_HF CYAN ("0x%04x")
#define CYAN_DF CYAN (FORMAT)
#define CYAN_M CYAN ("$mem[0x%1x]")

#define PURPLE_S PURPLE ("%s")

#define CYAN_LS CYAN ("%.*s")
#define PURPLE_LS PURPLE ("%.*s")

#endif
