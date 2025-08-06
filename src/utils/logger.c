#include "log/logger.h"
#include "color.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define INFO "[INFO]: "
#define WARN YELLOW ("[WARN]: ")
#define ERR RED ("[ERROR]: ")

void
info_print (const char *caller_func, char *fmt, ...)
{
#ifdef DEBUG
  va_list args;
  va_start (args, fmt);
  fprintf (stderr, INFO);
  fprintf (stderr, "in %s: ", caller_func);
  vfprintf (stderr, fmt, args);
  putc ('\n', stderr);
  va_end (args);
  fflush (stderr);
#else
  (void) caller_func;
  (void) fmt;
#endif // !DEBUG
}

void
warn_print (const char *caller_func, char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  fprintf (stderr, WARN);
  fprintf (stderr, "in %s: ", caller_func);
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
  fprintf (stderr, "in %s: ", caller_func);
  vfprintf (stderr, fmt, args);
  putc ('\n', stderr);
  va_end (args);
  exit (1);
}
