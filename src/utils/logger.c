#include "log/logger.h"
#include "color.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct
{
  char *src;
  uint32_t idx;
} log;

static log logger;

#define INFO "[INFO]: "
#define WARN YELLOW ("[WARN]: ")
#define ERR RED ("[ERROR]: ")

void
log_info (char *msg)
{
  printf (INFO "%s\n", logger.src);
  printf (FORMAT ": ", logger.idx);
  printf ("%s\n", msg);
  return;
}

void
log_warn (char *msg)
{
  printf (WARN "%s\n", logger.src);
  printf (FORMAT ": ", logger.idx);
  printf ("%s\n", msg);
  return;
}

_Noreturn void
log_err (char *msg)
{
  printf (ERR "%s\n", logger.src);
  printf (FORMAT ": ", logger.idx);
  printf ("%s\n", msg);
  exit (-1);
}

void
set_log (char *src, uint32_t pc)
{
  logger.src = src;
  logger.idx = pc;
}
