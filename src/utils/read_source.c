#define _GNU_SOURCE
#include "read_source.h"
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
#define MAX_LINE_LEN 0x180
#define MAX_FILE_LEN 0x10000 // 1MiB

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
increase_map (void); // forward declaration for fail_fast_invalid_source

static void
clear_color (char *text, uint32_t line_len)
{
  char *cursor = memchr (text, '\x1b', line_len);
  if (!cursor)
    return;
  char *colorstart = NULL;
  char *clear = cursor;

  for (; *cursor != '\0'; cursor++)
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
  // but it may not end with lf, we add one to simplify following process
  if (*(source + current - 1) != lf)
    {
      if (current % GROW_LEN == 0 || current % GROW_LEN == GROW_LEN - 1)
        // we are at page boundry!
        // allocate some more page shouldn't hurt too much performance
        increase_map ();
      if (file_type == UNIX || file_type == MACOS)
        source[current] = lf;
      else // file_type == WINDOWS
        memcpy (source + current, "\r\n", 2);
      current++; // memchr only check \r or \n,
                 // so adding 1 byte could include windows case
    }
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
  int fd = fileno (read_fp); // give compiler some hint

  do
    {
      increase_map ();
      read_len = read (fd, source + current, GROW_LEN);
      if (read_len == (uint32_t)-1)
        error ("read :%s", strerror (errno));
      current += read_len;
      if (current > MAX_FILE_LEN)
        error ("%s", FILE_TOO_LARGE);
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

#define MIN(a, b) ((a) < (b) ? (a) : (b))
char *
next_line (void)
{
  static uint32_t cursor = 0;
  if (cursor >= current)
    return NULL;
  char *read_ptr = source + cursor;
  char *brk;
  switch (file_type)
    {
    case UNIX:
      brk = memchr (read_ptr, '\n', current - cursor);
      *brk = '\0';
      cursor = brk + 1 - source;
      break;
    case MACOS:
      brk = memchr (read_ptr, '\r', current - cursor);
      *brk = '\0';
      cursor = brk + 1 - source;
      break;
    case WINDOWS:
      // even if file is malformed, this could be safe (\n\n)
      brk = memchr (read_ptr, '\n', current - cursor);
      memcpy (brk - 1, "\0", 2);
      cursor = brk + 1 - source;
      break;
    default:
      assert (!"file_type is neither UNIX, MACOS nor WINDOWS");
    }
  clear_color (read_ptr, brk - read_ptr);
  return read_ptr;
}
