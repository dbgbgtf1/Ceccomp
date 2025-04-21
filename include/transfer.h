#ifndef TRANSFER
#define TRANSFER

#include <stdint.h>
#include "../include/color.h"

#define syscall_nr PURPLE("$syscall_nr")
#define architecture PURPLE("$arch")
#define low_pc PURPLE("low pc")
#define high_pc PURPLE("high pc")
#define low_arg0 PURPLE("low args[0]")
#define low_arg1 PURPLE("low args[1]")
#define low_arg2 PURPLE("low args[2]")
#define low_arg3 PURPLE("low args[3]")
#define low_arg4 PURPLE("low args[4]")
#define low_arg5 PURPLE("low args[5]")
#define high_arg0 PURPLE("high args[0]")
#define high_arg1 PURPLE("high args[1]")
#define high_arg2 PURPLE("high args[2]")
#define high_arg3 PURPLE("high args[3]")
#define high_arg4 PURPLE("high args[4]")
#define high_arg5 PURPLE("high args[5]")

#ifdef __cplusplus
extern "C" {
#endif

extern const char *const
ARCH2STR (uint32_t token);

extern const uint32_t STR2ARCH(const char* const);

extern const char *const
ABS2STR(uint32_t offset);

extern const char *const
RETVAL2STR (const uint32_t retval);

#ifdef __cplusplus
}
#endif

#endif
