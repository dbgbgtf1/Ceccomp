#ifndef ERROR
#define ERROR

// args err
#define UNABLE_OPEN_FILE "unable to open file"
#define INVALID_ARCH "invalid arch"
#define INVALID_PRINT_MODE "invalid print mode"
#define SUPPORT_ARCH                                                          \
  STR_ARCH_X86                                                                \
  " " STR_ARCH_X86_64 " " STR_ARCH_X32 " " STR_ARCH_ARM " " STR_ARCH_AARCH64  \
  " " STR_ARCH_LOONGARCH64 " " STR_ARCH_M68K " " STR_ARCH_MIPS                \
  " " STR_ARCH_MIPSEL " " STR_ARCH_MIPS64 " " STR_ARCH_MIPSEL64               \
  " " STR_ARCH_MIPS64N32 " " STR_ARCH_MIPSEL64N32 " " STR_ARCH_PARISC         \
  " " STR_ARCH_PARISC64 " " STR_ARCH_PPC64 " " STR_ARCH_PPC                   \
  " " STR_ARCH_PPC64LE " " STR_ARCH_S390X " " STR_ARCH_S390                   \
  " " STR_ARCH_RISCV64
#define INVALID_SYSNR "invalid syscall nr"
#define INVALID_SYS_ARGS "invalid syscall args"
#define INVALID_IP "invalid instruction pointer"
#define INVALID_PID "invalid pid"

// text->raw err
#define INVALID_OPERATOR "invalid operator"
#define INVALID_CMPENUM "invalid cmp sym enum"
#define INVALID_ALUENUM "invalid alu sym enum"

#define INVALID_RIGHT_VAL "invalid right value"
#define INVALID_LEFT_VAR "invalid left valiable"

#define INVALID_MEM_IDX "invalid idx of $mem"
#define INVALID_MEM "invalid $mem"

#define INVALID_IF "invalid if line"
#define INVALID_RET "invalid ret line"

#define BRACE_WRAP_CONDITION "use (condition) to wrap condition"
#define GOTO_AFTER_CONDITION "use 'goto' after (condition)"
#define LINE_NR_AFTER_GOTO "line number to go after 'goto'"
#define LINE_NR_AFTER_ELSE "line number to go after ',else goto'"
#define INVALID_NR_AFTER_GOTO "invalid number after goto"

#define INVALID_ASM_CODE "invalid asm code"

#define INVALID_RET_VAL "invalid ret value"

// text->raw
#define INVALID_OFFSET_ABS "invalid offset of seccomp_data"

#define INVALID_CLASS "invalid class"

#define INVALID_REG_A_VAL "invalid reg A val"
#define INVALID_REG_X_VAL "invalid reg X val"
#define INVALID_REG_MEM_VAL(idx) "invalid reg mem" idx "val"
#define INVALID_A_STATUS "invalid A status"

#define INVALID_MISC_MODE "invalid misc mode"
#define INVALID_RET_MODE "invalid ret mode"
#define INVALID_JMP_MODE "invalid jmp mode"
#define INVALID_JMP_SRC "invalid jmp src"
#define INVALID_JT_JF "invalid jt and jf both 0"
#define INVALID_ALU_OP "invalid alu operation"
#define INVALID_ALU_SRC "invalid alu src"
#define INVALID_LD_LDX_MODE "invalid ld or ldx mode"

// trace err
#define SYS_ADMIN_OR_KERNEL                                                   \
  "run with CAP_SYS_ADMIN capability when trace pid\nand kernel pid can't "   \
  "be trace"
#define NOT_AN_CBPF "non-cbpf found, can't resolve, but continue"

#define PEXIT(str, ...)                                                       \
  {                                                                           \
    printf (str "\n", __VA_ARGS__);                                           \
    exit (0);                                                                 \
  }

#define PERROR(str)                                                           \
  {                                                                           \
    perror (str);                                                             \
    exit (0);                                                                 \
  }

#endif
