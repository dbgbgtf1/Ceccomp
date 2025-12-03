#include "vector.h"
#include "log/error.h"
#include "log/logger.h"
#include <errno.h>
#include <stddef.h>
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

void
init_vector (vector_t *vector)
{
  vector->count = 0;
  vector->capacity = 8;
  vector->arr = reallocate (vector->arr, sizeof (size_t) * vector->capacity);
}

void
free_vector (vector_t *vector)
{
  vector->count = 0;
  vector->capacity = 0;
  vector->arr = reallocate (vector->arr, sizeof (size_t) * vector->capacity);
}

void
add_value (vector_t *vector, size_t value)
{
  if (vector->capacity <= vector->count)
    {
      vector->capacity *= 2;
      vector->arr
          = reallocate (vector->arr, sizeof (size_t) * vector->capacity);
    }
  vector->arr[vector->count++] = value;
}
