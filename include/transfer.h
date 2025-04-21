#ifndef TRANSFER
#define TRANSFER

#include <stdint.h>

#define syscall_nr "syscall_nr"
#define architecture "arch"

#ifdef __cplusplus
extern "C" {
#endif

const char *const
ARCH2STR (uint32_t token);

const uint32_t STR2ARCH(const char* const);

const char *const
ABS2STR(uint32_t offset);

const char *const
RETVAL2STR (const uint32_t retval);

#ifdef __cplusplus
}
#endif

#endif
