#ifndef TRANSFER
#define TRANSFER

#include <stdint.h>

#define SYSCALL_NR "$syscall_nr"
#define ARCHITECTURE "$arch"
#define LOW_PC "$low_pc"
#define HIGH_PC "$high_pc"
#define LOW_ARG0 "$low_args[0]"
#define LOW_ARG1 "$low_args[1]"
#define LOW_ARG2 "$low_args[2]"
#define LOW_ARG3 "$low_args[3]"
#define LOW_ARG4 "$low_args[4]"
#define LOW_ARG5 "$low_args[5]"
#define HIGH_ARG0 "$high_args[0]"
#define HIGH_ARG1 "$high_args[1]"
#define HIGH_ARG2 "$high_args[2]"
#define HIGH_ARG3 "$high_args[3]"
#define HIGH_ARG4 "$high_args[4]"
#define HIGH_ARG5 "$high_args[5]"

#define STR_ARCH_X86 "i386"
#define STR_ARCH_X86_64 "x86_64"
#define STR_ARCH_X32 "x32"
#define STR_ARCH_ARM "arm"
#define STR_ARCH_AARCH64 "aarch64"
#define STR_ARCH_LOONGARCH64 "loongarch64"
#define STR_ARCH_M68K "m68k"
#define STR_ARCH_MIPS "mips"
#define STR_ARCH_MIPSEL "mipsel"
#define STR_ARCH_MIPS64 "mips64"
#define STR_ARCH_MIPSEL64 "mipsel64"
#define STR_ARCH_MIPS64N32 "mips64n32"
#define STR_ARCH_MIPSEL64N32 "mipsel64n32"
#define STR_ARCH_PARISC "parisc"
#define STR_ARCH_PARISC64 "parisc64"
#define STR_ARCH_PPC64 "ppc64"
#define STR_ARCH_PPC64LE "ppc64le"
#define STR_ARCH_PPC "ppc"
#define STR_ARCH_S390X "s390x"
#define STR_ARCH_S390 "s390"
#define STR_ARCH_RISCV64 "riscv64"

#ifdef __cplusplus
extern "C"
{
#endif

  extern char *ARCH2STR (uint32_t token);

  extern uint32_t STR2ARCH (char *);

  extern char *ABS2STR (uint32_t offset);

  extern uint32_t STR2ABS (char *str);

  extern char *RETVAL2STR (uint32_t retval);

  extern int32_t STR2RETVAL (char *str);

  extern int32_t STR2REG (char *str);

  extern int32_t STR2MEM (char *str);

  extern char *REG_MEM2STR (uint32_t offset);

#ifdef __cplusplus
}
#endif

#endif
