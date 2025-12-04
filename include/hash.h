#ifndef HASH
#define HASH

#include <stddef.h>
#include <stdint.h>

typedef struct bucket_t bucket_t;

typedef struct
{
  uint16_t len;
  char *string;
} key_t;

struct bucket_t
{
  bucket_t *next;
  uint16_t line_nr;
  key_t key_tmp;
};

typedef struct
{
  uint32_t count;
  uint32_t capacity;
  bucket_t *bucket;
} table_t;

extern void insert_key (key_t key_tmp, uint16_t line_nr);

extern void free_key (key_t key_tmp);

extern uint16_t find_key (key_t key_tmp);

extern void init_table ();

extern void free_table ();

#endif
