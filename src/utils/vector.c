#include "vector.h"
#include "log/logger.h"
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void *
reallocate (void *p, size_t new_size)
{
  if (new_size == 0)
    {
      free (p);
      return NULL;
    }

  p = realloc (p, new_size);
  if (p == NULL)
    error ("realloc: %s", strerror (errno));

  return p;
}

#define UPDATE_VECTOR                                                         \
  v->data = reallocate (v->data, v->capacity * v->elem_size);

void
init_vector (vector_t *v, size_t elem_size)
{
  v->count = 0;
  v->capacity = 0x10;
  v->elem_size = elem_size;
  v->data = NULL;
  UPDATE_VECTOR;
}

void
free_vector (vector_t *v)
{
  v->count = 0;
  v->capacity = 0;
  v->elem_size = 0;
  UPDATE_VECTOR;
}

void *
push_vector (vector_t *v, void *elem)
{
  if (v->count == v->capacity)
    {
      v->capacity *= 2;
      UPDATE_VECTOR;
    }

  void *dst = v->data + v->count * v->elem_size;
  memcpy (dst, elem, v->elem_size);
  v->count++;
  return dst;
}

void *
get_vector (vector_t *v, uint32_t idx)
{
  return v->data + idx * v->elem_size;
}
