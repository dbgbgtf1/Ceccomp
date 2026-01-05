#ifndef VECTOR
#define VECTOR

#include <stddef.h>
#include <stdint.h>

// when a vector store statement_t
// the statement must be ordered by code_nr
// code_nr and text_nr both starts from 1
// statement at index 0 should be ignored
// empty lines are skipped and dealed with text_nr
// eof_lines are skipped, too.

typedef struct
{
  uint32_t count;
  uint32_t capacity;
  size_t elem_size;
  void *data;
} vector_t;

extern void *reallocate (void *p, size_t new_size);

extern void init_vector (vector_t *v, size_t elem_size);

extern void free_vector (vector_t *v);

extern void *push_vector (vector_t *v, void *elem);

extern void *get_vector (vector_t *v, uint32_t idx);

#endif
