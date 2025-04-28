#define UNABLE_OPEN_FILE "unable to open file"
#define INVALID_ARCH "invalid arch"
#define SUPPORT_ARCH "X86 X86_64 X32 ARM AARCH64 MIPS MIPSEL MIPSEL64" \
                     "MIPSEL64N32 PARSIC PARSIC64 PPC PPC64 PPC64LE " \
                     "S390 S390X RISCV64"

#define INVALID_OPERATOR "invalid operator"
#define INVALID_SYMENUM "invalid sym enum"

#define INVALID_RIGHT INVALID_RIGHT_VALUE " or " INVALID_RIGHT_VAR
#define INVALID_RIGHT_VALUE "invalid right value"
#define INVALID_RIGHT_VAR "invalid right variable"

#define INVALID_LEFT_VAR "invalid left variable"

#define INVALID_MEM_IDX "invalid idx of $mem"
#define INVALID_MEM "invalid $mem"




#define INVALID_IF "invalid if line"
#define INVALID_RET "invalid ret line"


#define PEXIT(str, ...)                                                       \
  {                                                                           \
    printf (str "\n", __VA_ARGS__);                                           \
    exit (0);                                                                 \
  }
