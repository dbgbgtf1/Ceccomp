#include "log/logger.h"
#include "color.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define LOG_CYAN(str) ((log_color_enable) ? (CYANCLR str CLR) : str)
#define LOG_BLUE(str) ((log_color_enable) ? (BLUECLR str CLR) : str)
#define LOG_YELLOW(str) ((log_color_enable) ? (YELLOWCLR str CLR) : str)
#define LOG_RED(str) ((log_color_enable) ? (REDCLR str CLR) : str)

#define DEBUG_PREFIX LOG_CYAN ("[DEBUG]: ")
#define INFO LOG_BLUE ("[INFO]: ")
#define WARN LOG_YELLOW ("[WARN]: ")
#define ERR LOG_RED ("[ERROR]: ")

bool color_tmp;

void
debug_print (const char *caller_func, char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  fprintf (stderr, DEBUG_PREFIX);

#ifdef DEBUG
  fprintf (stderr, "in %s: ", caller_func);
#else
  (void)caller_func;
#endif

  vfprintf (stderr, fmt, args);
  putc ('\n', stderr);
  va_end (args);
  fflush (stderr);
}

void
info_print (const char *caller_func, char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  fprintf (stderr, INFO);

#ifdef DEBUG
  fprintf (stderr, "in %s: ", caller_func);
#else
  (void)caller_func;
#endif

  vfprintf (stderr, fmt, args);
  putc ('\n', stderr);
  va_end (args);
  fflush (stderr);
}

void
warn_print (const char *caller_func, char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  fprintf (stderr, WARN);

#ifdef DEBUG
  fprintf (stderr, "in %s: ", caller_func);
#else
  (void)caller_func;
#endif

  vfprintf (stderr, fmt, args);
  putc ('\n', stderr);
  va_end (args);
  fflush (stderr);
}

void
error_print (const char *caller_func, char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  fprintf (stderr, ERR);

#ifdef DEBUG
  fprintf (stderr, "in %s: ", caller_func);
#else
  (void)caller_func;
#endif

  vfprintf (stderr, fmt, args);
  putc ('\n', stderr);
  va_end (args);
  exit (1);
}
