#ifndef PARSEARGS
#define PARSEARGS

#include <stdbool.h>

extern bool parse_option_mode_enable (int argc, char *argv[], char *token);

extern char *parse_option_mode (int argc, char *argv[], char *token);

extern char *get_arg (int argc, char *argv[]);

#endif
