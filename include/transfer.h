#ifndef TRANSFER
#define TRANSFER

#include <stdint.h>

#define syscall_nr "$syscall_nr"
#define architecture "$arch"
#define low_pc "$low_pc"
#define high_pc "$high_pc"
#define low_arg0 "$low_args[0]"
#define low_arg1 "$low_args[1]"
#define low_arg2 "$low_args[2]"
#define low_arg3 "$low_args[3]"
#define low_arg4 "$low_args[4]"
#define low_arg5 "$low_args[5]"
#define high_arg0 "$high_args[0]"
#define high_arg1 "$high_args[1]"
#define high_arg2 "$high_args[2]"
#define high_arg3 "$high_args[3]"
#define high_arg4 "$high_args[4]"
#define high_arg5 "$high_args[5]"

#ifdef __cplusplus
extern "C"
{
#endif

  extern char *ARCH2STR (uint32_t token);

  extern uint32_t STR2ARCH (char *);

  extern char *ABS2STR (uint32_t offset);

  extern uint32_t STR2ABS (char *str);

  extern char *RETVAL2STR (uint32_t retval);

  extern uint32_t STR2RETVAL (char *str);

  extern uint32_t STR2REG (char *str);

  extern char *REG2STR (uint32_t offset);

#ifdef __cplusplus
}
#endif

#endif
