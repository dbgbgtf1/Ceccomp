#ifndef COLOR
#define COLOR

#define FORMAT "%04d"

#define CLR "\e[0m"

#define REDCLR "\e[31m"
#define GREENCLR "\e[32m"
#define YELLOWCLR "\e[33m"
#define CYANCLR "\e[36m"
#define PURPLECLR "\e[95m"
#define LIGHTCLR "\e[90m"

#define RED(str) REDCLR str CLR
#define GREEN(str) GREENCLR str CLR
#define YELLOW(str) YELLOWCLR str CLR
#define CYAN(str) CYANCLR str CLR
#define PURPLE(str) PURPLECLR str CLR
#define LIGHT(str) LIGHTCLR str CLR

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
