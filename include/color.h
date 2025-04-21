#ifndef COLOR
#define COLOR

#define CLR "\e[0m"

#define RED(str) "\e[31m" str CLR
#define YELLOW(str) "\e[33m" str CLR
#define GREEN(str) "\e[32m" str CLR
#define BLUE(str) "\e[36m" str CLR
#define PURPLE(str) "\e[95m" str CLR

#define BLUE_A BLUE ("A")
#define BLUE_X BLUE ("X")
#define BLUE_S BLUE ("%s")
#define BLUE_H BLUE ("0x%04x")

#endif
