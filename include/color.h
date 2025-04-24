#ifndef COLOR
#define COLOR

#define FORMAT "%04d"

#define CLR "\e[0m"

#define UNDERLINE(str) "\e[4m" str CLR
#define RED(str) "\e[31m" str CLR
#define YELLOW(str) "\e[33m" str CLR
#define GREEN(str) "\e[32m" str CLR
#define BLUE(str) "\e[36m" str CLR
#define PURPLE(str) "\e[95m" str CLR
#define LIGHTCOLOR(str) "\e[90m" str CLR

#define BLUE_A BLUE ("$A")
#define BLUE_X BLUE ("$X")
#define BLUE_S BLUE ("%s")
#define BLUE_H BLUE ("0x%x")
#define BLUE_HF BLUE ("0x%04x")
#define BLUE_DF BLUE (FORMAT)
#define BLUE_M BLUE ("$mem[0x%1x]")

#define PURPLE_S PURPLE ("%s")

#define BLUE_LS BLUE ("%.*s")
#define PURPLE_LS PURPLE ("%.*s")

#endif
