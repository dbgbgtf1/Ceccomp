#ifndef ARCH_TRANS
#define ARCH_TRANS

#include "main.h"
#include <seccomp.h>
#include <stdint.h>

extern uint32_t internal_arch_to_scmp_arch (uint32_t internal_arch);

extern uint32_t scmp_arch_to_internal_arch (uint32_t scmp_arch);

extern uint32_t str_to_scmp_arch (char *str);

extern string_t *scmp_arch_to_str (uint32_t scmp_arch);

#endif
