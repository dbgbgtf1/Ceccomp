#ifndef STRING_PILE
#define STRING_PILE

#include "main.h"
#include <stddef.h>

/**
 * Initialize string pile with init_size to mmap. init_size will be aligned up
 * to 0x1000.
 * Returns if mmap succeeded.
 */
extern bool init_pile (size_t init_size);

/**
 * Slice some mmap memory to store syscall name.
 * sysname: syscall name string. NULL-terminated.
 * arch: a token from token_pairs. if not NULL, store "arch.sysname", else
 * "sysname".
 */
extern string_t persist_object (const char *sysname, const string_t *arch);

extern void free_pile (void);

#endif
