#include "hash.h"
#include "log/error.h"
#include "log/logger.h"
#include "vector.h"
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static table_t table;

static uint32_t
hashString (hkey_t *key)
{
  uint32_t hash = 2166136261u;
  for (int i = 0; i < key->len; i++)
    {
      hash ^= (uint8_t)key->string[i];
      hash *= 16777619;
    }
  return hash;
}

static bucket_t *
hash_bucket (hkey_t *key)
{
  uint32_t hash = hashString (key);
  uint32_t idx = hash % table.capacity;
  return &table.bucket[idx];
}

static bucket_t *
creat_bucket (hkey_t *key, uint16_t line_nr)
{
  bucket_t *bucket = NULL;
  bucket = reallocate (bucket, sizeof (bucket_t) + key->len + 1);

  bucket->key = *key;
  bucket->line_nr = line_nr;
  bucket->next = NULL;
  return bucket;
}

void
insert_key (hkey_t *key, uint16_t line_nr)
{
  bucket_t *bucket = hash_bucket (key);

  bucket_t *bucket_new = creat_bucket (key, line_nr);
  bucket_new->next = bucket->next;
  bucket->next = bucket_new;

  table.count++;
}

static void
free_next_bucket (bucket_t *bucket)
{
  bucket_t *bucket_next = bucket->next->next;
  reallocate (bucket->next, 0);
  bucket->next = bucket_next;
  table.count--;
}

void
free_key (hkey_t *key)
{
  bucket_t *bucket = hash_bucket (key);

  while (bucket->next)
    {
      if (strncmp (bucket->next->key.string, key->string, key->len))
        bucket = bucket->next;
      else
        {
          free_next_bucket (bucket);
          return;
        }
    }

  error (CANNOT_FIND_LABEL, key->len, key->string);
}

uint16_t
find_key (hkey_t *key)
{
  bucket_t *bucket = hash_bucket (key);

  while (bucket->next)
    {
      if (strncmp (bucket->next->key.string, key->string, key->len))
        bucket = bucket->next;
      else
        return bucket->next->line_nr;
    }

  error (CANNOT_FIND_LABEL, key->len, key->string);
}

void
init_table ()
{
  table.count = 0;
  table.capacity = 0x100;
  table.bucket = reallocate (NULL, sizeof (bucket_t) * table.capacity);
  memset (table.bucket, '\0', sizeof (bucket_t) * table.capacity);
}

void
free_table ()
{
  while (table.capacity)
    {
      bucket_t *bucket = &table.bucket[--table.capacity];
      while (bucket->next)
        free_next_bucket (bucket);
    }

  assert (table.count == 0 && table.capacity == 0);

  reallocate (table.bucket, sizeof (bucket_t) * table.capacity);
}
