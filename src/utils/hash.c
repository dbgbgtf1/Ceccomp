#include "hash.h"
#include "log/error.h"
#include "log/logger.h"
#include "vector.h"
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static uint32_t
hashString (key_t key_tmp)
{
  uint32_t hash = 2166136261u;
  for (int i = 0; i < key_tmp.len; i++)
    {
      hash ^= (uint8_t)key_tmp.string[i];
      hash *= 16777619;
    }
  return hash;
}

static bucket_t *
hash_bucket (table_t *table, key_t key_tmp)
{
  uint32_t hash = hashString (key_tmp);
  uint32_t idx = hash % table->capacity;
  return &table->bucket[idx];
}

static bucket_t *
creat_bucket (key_t key_tmp, uint16_t line_nr)
{
  bucket_t *bucket = NULL;
  bucket = reallocate (bucket, sizeof (bucket_t) + key_tmp.len + 1);

  bucket->key_tmp = key_tmp;

  bucket->line_nr = line_nr;
  bucket->next = NULL;
  return bucket;
}

void
insert_key (table_t *table, key_t key_tmp, uint16_t line_nr)
{
  bucket_t *bucket = hash_bucket (table, key_tmp);

  bucket_t *bucket_new = creat_bucket (key_tmp, line_nr);
  bucket_new->next = bucket->next;
  bucket->next = bucket_new;

  table->count++;
}

static void
free_next_bucket (table_t *table, bucket_t *bucket)
{
  bucket_t *bucket_next = bucket->next->next;
  reallocate (bucket->next, 0);
  bucket->next = bucket_next;
  table->count--;
}

void
free_key (table_t *table, key_t key_tmp)
{
  bucket_t *bucket = hash_bucket (table, key_tmp);

  while (bucket->next)
    {
      if (strncmp (bucket->next->key_tmp.string, key_tmp.string, key_tmp.len))
        bucket = bucket->next;
      free_next_bucket (table, bucket);
      return;
    }

  error (CANNOT_FIND_VALUE, key_tmp.len, key_tmp.string);
}

uint16_t
find_key (table_t *table, key_t key_tmp)
{
  bucket_t *bucket = hash_bucket (table, key_tmp);

  while (bucket->next)
    {
      if (strncmp (bucket->next->key_tmp.string, key_tmp.string, key_tmp.len))
        bucket = bucket->next;
      return bucket->next->line_nr;
    }

  error (CANNOT_FIND_VALUE, key_tmp.len, key_tmp.string);
}

void
init_table (table_t *table)
{
  table->count = 0;
  table->capacity = 0x100;
  table->bucket = reallocate (table, sizeof (bucket_t) * table->capacity);
  memset (table->bucket, '\0', sizeof (bucket_t) * table->capacity);
}

void
free_table (table_t *table)
{
  while (table->capacity--)
    {
      bucket_t *bucket = &table->bucket[table->capacity];
      while (bucket->next)
        free_next_bucket (table, bucket);
    }

  assert (table->count == 0 && table->capacity == 0);

  table->bucket = reallocate (table, sizeof (bucket_t) * table->capacity);
}
