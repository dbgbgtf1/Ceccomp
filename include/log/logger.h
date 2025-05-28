#ifndef LOGGER
#define LOGGER

#include <stdint.h>

extern void log_info (char *msg);

extern void log_warn (char *msg);

extern _Noreturn void log_err (char *msg);

extern void set_log (char *src, uint32_t pc);

#endif
