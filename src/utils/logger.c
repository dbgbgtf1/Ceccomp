#include "log/logger.h"
#include "color.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define DEBUG_PREFIX "[DEBUG]: "
#define INFO BLUE ("[INFO]: ")
#define WARN YELLOW ("[WARN]: ")
#define ERR RED ("[ERROR]: ")

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
