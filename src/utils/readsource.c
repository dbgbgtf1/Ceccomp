#define _GNU_SOURCE
#include "readsource.h"
#include "log/logger.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define GROW_LEN 0x4000

char *source = NULL;
uint32_t current = 0;
uint32_t map_len = 0;

static void
clear_color (char *text)
{
  char *colorstart = NULL;
  char *clear = text;

  for (char *cursor = text; *cursor != '\0'; cursor++)
    {
      if (!colorstart && *cursor != '\x1b')
        *clear++ = *cursor;
      else if (!colorstart && *cursor == '\x1b')
        colorstart = cursor;
      else if (colorstart && *cursor == 'm')
        colorstart = NULL;
      // else skip
    }
  *clear = '\0';
}

static void
init_map ()
{
  source = mmap (NULL, GROW_LEN, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (source == MAP_FAILED)
    error ("mmap: %s", strerror (errno));

  map_len = GROW_LEN;
}

static void
increase_map ()
{
  if (source == NULL)
    return init_map ();

  source = mremap (source, map_len, map_len + GROW_LEN, MREMAP_MAYMOVE);
  if (source == MAP_FAILED)
    error ("mremap: %s", strerror (errno));

  map_len += GROW_LEN;
}

char *
read_source (FILE *read_fp)
{
  uint32_t read_len = 0;

  do
    {
      increase_map ();
      read_len = read (fileno (read_fp), source + current, GROW_LEN);
      if (read_len == (uint32_t)-1)
        error ("read :%s", strerror (errno));
      current += read_len;
    }
  while (read_len == GROW_LEN);

  clear_color (source);

  return source;
}

void
free_source ()
{
  munmap (source, map_len);
}
