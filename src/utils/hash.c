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
hashString (char *key, uint16_t len)
{
  uint32_t hash = 2166136261u;
  for (int i = 0; i < len; i++)
    {
      hash ^= (uint8_t)key[i];
      hash *= 16777619;
    }
  return hash;
}

static bucket_t *
hash_bucket (table_t *table, char *key, uint16_t len)
{
  uint32_t hash = hashString (key, len);
  uint32_t idx = hash % table->capacity;
  return &table->bucket[idx];
}

static bucket_t *
creat_bucket (char *key, uint16_t len, uint16_t line_nr)
{
  bucket_t *bucket = NULL;
  bucket = reallocate (bucket, sizeof (bucket_t) + len + 1);

  memcpy (bucket->string, key, len);
  bucket->string[len] = '\0';

  bucket->line_nr = line_nr;
  bucket->next = NULL;
  return bucket;
}

void
insert_key (table_t *table, char *key, uint16_t len, uint16_t line_nr)
{
  bucket_t *bucket = hash_bucket (table, key, len);

  bucket_t *bucket_new = creat_bucket (key, len, line_nr);
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
free_key (table_t *table, char *key, uint16_t len)
{
  bucket_t *bucket = hash_bucket (table, key, len);

  while (bucket->next)
    {
      if (strncmp (bucket->next->string, key, len))
        bucket = bucket->next;
      free_next_bucket (table, bucket);
      return;
    }

  error (CANNOT_FIND_VALUE, len, key);
}

uint16_t
find_key (table_t *table, char *key, uint16_t len)
{
  bucket_t *bucket = hash_bucket (table, key, len);

  while (bucket->next)
    {
      if (strncmp (bucket->next->string, key, len))
        bucket = bucket->next;
      return bucket->next->line_nr;
    }

  error (CANNOT_FIND_VALUE, len, key);
}

void
init_table (table_t *table)
{
  table->count = 0;
  table->capacity = 0x30;
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
