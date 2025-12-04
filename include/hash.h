#ifndef HASH
#define HASH

#include <stddef.h>
#include <stdint.h>

typedef struct bucket_t bucket_t;

struct bucket_t
{
  bucket_t *next;
  uint16_t line_nr;
  uint16_t len;
  char *string;
};

typedef struct
{
  uint32_t count;
  uint32_t capacity;
  bucket_t *bucket;
} table_t;

// clang-format off
extern void insert_key (table_t *table, char *key, uint16_t len, uint16_t line_nr);
// clang-format on

extern void free_key (table_t *table, char *key, uint16_t len);

extern uint16_t find_key (table_t *table, char *key, uint16_t len);

extern void init_table (table_t *table);

extern void free_table (table_t *table);

#endif
