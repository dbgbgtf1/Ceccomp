#ifndef ERROR
#define ERROR

#include "i18n.h"

// args err
#define UNABLE_OPEN_FILE _ ("Unable to open file")
#define INVALID_ARCH _ ("Invalid arch")
#define INVALID_PRINT_MODE _ ("Invalid print mode")
#define INVALID_COLOR_MODE _ ("Invalid color mode")
#define SUPPORT_ARCH                                                          \
  STR_ARCH_X86                                                                \
  " " STR_ARCH_X86_64 " " STR_ARCH_X32 " " STR_ARCH_ARM " " STR_ARCH_AARCH64  \
  " " STR_ARCH_LOONGARCH64 " " STR_ARCH_M68K " " STR_ARCH_MIPS                \
  " " STR_ARCH_MIPSEL " " STR_ARCH_MIPS64 " " STR_ARCH_MIPSEL64               \
  " " STR_ARCH_MIPS64N32 " " STR_ARCH_MIPSEL64N32 " " STR_ARCH_PARISC         \
  " " STR_ARCH_PARISC64 " " STR_ARCH_PPC64 " " STR_ARCH_PPC                   \
  " " STR_ARCH_PPC64LE " " STR_ARCH_S390X " " STR_ARCH_S390                   \
  " " STR_ARCH_RISCV64
#define INVALID_SYSNR _ ("Invalid syscall_nr")
#define INVALID_SYS_ARGS _ ("Invalid syscall args")
#define INVALID_IP _ ("Invalid instruction pointer")
#define INVALID_PID _ ("Invalid pid")
#define INPUT_SYS_NR _ ("Please input syscall_nr to emu")
#define SYSTEM_ARCH_NOT_SUPPORTED                                             \
  _ ("Your system arch (%s) does not match any arch supported by "            \
     "libseccomp, please set an arch by -a manually")

// hash
#define CANNOT_FIND_VALUE _ ("Can not find value: %.*s")

#endif
