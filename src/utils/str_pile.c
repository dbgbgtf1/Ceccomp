#include "str_pile.h"
#include "main.h"
#include <assert.h>
#include <linux/prctl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>

static char *str_pile;
static char *pile_top;
static char *pile_cursor;

bool
init_pile (size_t init_size)
{
  size_t aligned = (init_size + 0xfff) & ~0xfff;
  str_pile = mmap (NULL, aligned, PROT_READ | PROT_WRITE,
                   MAP_ANON | MAP_PRIVATE, -1, 0);
  if (!str_pile)
    return false;
#ifdef PR_SET_VMA
  prctl (PR_SET_VMA, PR_SET_VMA_ANON_NAME, str_pile, aligned, "str pile");
#endif
  pile_cursor = str_pile;
  pile_top = str_pile + aligned;
  return true;
}

string_t
persist_object (const char *sysname, const string_t *arch)
{
  uint32_t syslen = strlen (sysname);
  uint32_t size;
  if (arch)
    size = arch->len + 1 + syslen; // arch.sysname
  else
    size = syslen; // sysname
  assert (pile_cursor + size <= pile_top);

  if (arch)
    {
      memcpy (pile_cursor, arch->start, arch->len);
      pile_cursor += arch->len;
      *pile_cursor++ = '.';
    }
  memcpy (pile_cursor, sysname, syslen);
  pile_cursor += syslen;

  return (string_t){ .start = pile_cursor - size, .len = size };
}

void
free_pile (void)
{
  assert (!munmap (str_pile, pile_top - str_pile));
}
