#include "arch_trans.h"
#include "token.h"
#include <seccomp.h>
#include <stdint.h>
#include <string.h>

uint32_t arch_pairs[] = {
  [ARCH_X86] = SCMP_ARCH_X86,
  [ARCH_I686] = SCMP_ARCH_X86,
  [ARCH_X86_64] = SCMP_ARCH_X86_64,
  [ARCH_X32] = SCMP_ARCH_X32,
  [ARCH_ARM] = SCMP_ARCH_ARM,
  [ARCH_AARCH64] = SCMP_ARCH_AARCH64,
  [ARCH_LONNGARCH64] = SCMP_ARCH_LOONGARCH64,
  [ARCH_M68K] = SCMP_ARCH_M68K,
  [ARCH_MIPSEL64N32] = SCMP_ARCH_MIPSEL64N32,
  [ARCH_MIPSEL64] = SCMP_ARCH_MIPSEL64,
  [ARCH_MIPSEL] = SCMP_ARCH_MIPSEL,
  [ARCH_MIPS64N32] = SCMP_ARCH_MIPS64N32,
  [ARCH_MIPS64] = SCMP_ARCH_MIPS64,
  [ARCH_MIPS] = SCMP_ARCH_MIPS,
  [ARCH_PARISC64] = SCMP_ARCH_PARISC64,
  [ARCH_PARISC] = SCMP_ARCH_PARISC,
  [ARCH_PPC64LE] = SCMP_ARCH_PPC64LE,
  [ARCH_PPC64] = SCMP_ARCH_PPC64,
  [ARCH_PPC] = SCMP_ARCH_PPC,
  [ARCH_S390X] = SCMP_ARCH_S390X,
  [ARCH_S390] = SCMP_ARCH_S390,
  [ARCH_RISCV64] = SCMP_ARCH_RISCV64,
};

uint32_t
internal_arch_to_scmp_arch (uint32_t arch)
{
  // ARCH_X86 = 0, so (arch >= ARCH_X86) is always true;
  if (arch <= ARCH_RISCV64)
    return arch_pairs[arch];

  return -1;
}

uint32_t
str_to_scmp_arch (char *str)
{
  for (uint32_t i = 0; i < ARCH_RISCV64; i++)
    {
      if (!strcmp (str, token_pairs[i]))
        return internal_arch_to_scmp_arch (i);
    }
  return -1;
}
