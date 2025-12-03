#ifndef VECTOR
#define VECTOR

#include <stddef.h>
#include <stdint.h>

typedef struct
{
  uint32_t count;
  uint32_t capacity;
  size_t *arr;
} vector_t;

extern void *reallocate (void *p, size_t new_size);

extern void init_vector (vector_t *vector);

extern void free_vector (vector_t *vector);

extern void add_value (vector_t *vector, size_t value);

#endif
