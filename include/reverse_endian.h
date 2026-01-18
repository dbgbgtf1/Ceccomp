#ifndef REVERSE_ENDIAN
#define REVERSE_ENDIAN

#include "main.h"
#include <byteswap.h>
#include <linux/audit.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/utsname.h>

static inline bool
need_reverse_endian (uint32_t target_scmp_arch)
{
  bool local_le;

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  local_le = false;
#else
  local_le = true;
#endif

  return ((bool)(target_scmp_arch & __AUDIT_ARCH_LE) ^ (local_le));
}

static inline void
reverse_endian (filter *f)
{
  f->code = bswap_16 (f->code);
  f->k = bswap_32 (f->k);
}

#endif
