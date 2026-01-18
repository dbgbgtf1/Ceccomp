#ifndef HASH
#define HASH

#include "main.h"
#include <stddef.h>
#include <stdint.h>

typedef string_t hkey_t;

// return 0 if successfully inserted; -1 for ENOMEM; 1 for duplicated key
extern int insert_key (hkey_t *key, uint16_t line_nr);

extern uint16_t find_key (hkey_t *key);

extern void init_table ();

extern void free_table ();

#endif
