#ifndef COLOR
#define COLOR

#define FORMAT "%04d"

#define CLR "\e[0m"

#define UNDERLINE(str) "\e[4m" str CLR
#define RED(str) "\e[31m" str CLR
#define YELLOW(str) "\e[33m" str CLR
#define GREEN(str) "\e[32m" str CLR
#define CYAN(str) "\e[36m" str CLR
#define PURPLE(str) "\e[95m" str CLR
#define LIGHTCOLOR(str) "\e[90m" str CLR

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
