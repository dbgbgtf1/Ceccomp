#ifndef ARCH_TRANS
#define ARCH_TRANS

#include <seccomp.h>
#include <stdint.h>

extern uint32_t internal_arch_to_scmp_arch (uint32_t arch);

extern uint32_t str_to_scmp_arch (char *str);

#endif
