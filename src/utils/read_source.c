#define _GNU_SOURCE
#include "readsource.h"
#include "i18n.h"
#include "log/error.h"
#include "log/logger.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define GROW_LEN 0x4000
#define MAX_LINE_LEN 0x300

typedef enum
{
  UNKNOWN,
  UNIX,
  WINDOWS,
  MACOS,
} file_type_t;
static file_type_t file_type = UNKNOWN;

static char *source = NULL;
static uint32_t current = 0;
static uint32_t map_len = 0;

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
fail_fast_invalid_source (void)
{
  const char *zero_byte = memchr (source, '\0', current);
  if (zero_byte)
    error (_ ("Found '\\0' file offset %lu, perhaps it's not a text file?"),
           zero_byte - source);
  register char lf = '\n';
  const char *line_start = source;
  uint32_t line_nr = 1;
  const char *line_break = memchr (source, lf, current);

  if (!line_break)
    {
      lf = '\r'; // no \n found? perhaps source file is from mac
      line_break = memchr (source, lf, current);
      file_type = MACOS;
      if (!line_break)
        error ("%s", FOUND_SUS_ZERO);
    }
  else
    {
      if (line_break == source || line_break[-1] != '\r')
        file_type = UNIX;
      else
        file_type = WINDOWS;
    }
  assert (file_type != UNKNOWN);

  if (line_break - line_start > MAX_LINE_LEN)
    error (FOUND_SUS_LINE, line_nr, MAX_LINE_LEN);

  line_start = line_break + 1;
  line_nr++;
  while (line_start + MAX_LINE_LEN <= source + current)
    {
      line_break = memchr (line_start, lf, MAX_LINE_LEN);
      if (!line_break)
        error (FOUND_SUS_LINE, line_nr, MAX_LINE_LEN);
      line_start = line_break + 1;
      line_nr++;
    }
  // the rest line is safe
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

  if (current + GROW_LEN <= map_len)
    return;

  source = mremap (source, map_len, map_len + GROW_LEN, MREMAP_MAYMOVE);
  if (source == MAP_FAILED)
    error ("mremap: %s", strerror (errno));

  map_len += GROW_LEN;
}

char *
init_source (FILE *read_fp)
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
  while (read_len > 0); // reading via char device may get less than GROW_LEN

  fail_fast_invalid_source ();

  return source;
}

void
free_source ()
{
  munmap (source, map_len);
}
