#ifndef ERROR
#define ERROR

// preprocess error macros
#define NOT_ENOUGH_ARGS "not enough args"
#define INVALID_ARG "invalid arg"
#define UNABLE_OPEN_FILE "unable to open file"
#define INVALID_ARCH "invalid arch"
#define INVALID_PRINT_MODE "invalid print mode"
#define SUPPORT_ARCH                                                          \
  "X86 X86_64 X32 ARM AARCH64 MIPS MIPSEL MIPSEL64"                           \
  "MIPSEL64N32 PARSIC PARSIC64 PPC PPC64 PPC64LE "                            \
  "S390 S390X RISCV64"
#define INVALID_SYSNR "invalid syscall nr"
#define INVALID_SYS_ARGS "invalid syscall args"
#define INVALID_PC "invalid instruction pointer"

// text->bpf error macros
#define INVALID_OPERATOR "invalid operator"
#define INVALID_SYMENUM "invalid sym enum"

#define INVALID_RIGHT_VALUE "invalid right value"
#define INVALID_RIGHT_VAR "invalid right variable"
#define INVALID_RIGHT INVALID_RIGHT_VALUE " or " INVALID_RIGHT_VAR

#define INVALID_LEFT_VAR "invalid left variable"

#define INVALID_MEM_IDX "invalid idx of $mem"
#define INVALID_MEM "invalid $mem"

#define INVALID_IF "invalid if line"
#define INVALID_RET "invalid ret line"

#define BRACE_WRAP_CONDITION "use (condition) to wrap condition"
#define GOTO_AFTER_CONDITION "use 'goto' after (condition)"
#define LINE_NR_AFTER_GOTO "line number to go after 'goto'"
#define LINE_NR_AFTER_ELSE "line number to go after ',else goto'"

#define INVALID_ASM_CODE "invalid asm code"

#define INVALID_RET_VAL "invalid ret value"

// bpf->text- error macros
#define UNKNOWN_OFFSET_ABS "unknown offset of seccomp_data"

#define PEXIT(str, ...)                                                       \
  {                                                                           \
    printf (str "\n", __VA_ARGS__);                                           \
    exit (0);                                                                 \
  }

#endif
