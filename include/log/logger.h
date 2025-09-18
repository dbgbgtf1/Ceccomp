#ifndef LOGGER
#define LOGGER

#include <sys/cdefs.h>
// clang-format off
__attribute__ ((noinline)) void debug_print (const char *caller_func, char *fmt, ...);

__attribute__ ((noinline)) void info_print (const char *caller_func, char *fmt, ...);

__attribute__ ((noinline)) void warn_print (const char *caller_func, char *fmt, ...);

__attribute__ ((noinline)) __attribute__ ((noreturn)) void error_print (const char *caller_func, char *fmt, ...);
// clang-format on

#ifdef DEBUG
#define debug(fmt, ...) debug_print (__func__, fmt, __VA_ARGS__)
#else
#define debug(fmt, ...) ;
#endif // !DEBUG

#define info(fmt, ...) info_print (__func__, fmt, __VA_ARGS__)
#define warn(fmt, ...) warn_print (__func__, fmt, __VA_ARGS__)
#define error(fmt, ...) error_print (__func__, fmt, __VA_ARGS__)

#endif
