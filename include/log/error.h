#ifndef ERROR
#define ERROR

// args err
#define UNABLE_OPEN_FILE "Unable to open file"
#define INVALID_ARCH "Invalid arch"
#define INVALID_PRINT_MODE "Invalid print mode"
#define INVALID_COLOR_MODE "Invalid color mode"
#define SUPPORT_ARCH                                                          \
  STR_ARCH_X86                                                                \
  " " STR_ARCH_X86_64 " " STR_ARCH_X32 " " STR_ARCH_ARM " " STR_ARCH_AARCH64  \
  " " STR_ARCH_LOONGARCH64 " " STR_ARCH_M68K " " STR_ARCH_MIPS                \
  " " STR_ARCH_MIPSEL " " STR_ARCH_MIPS64 " " STR_ARCH_MIPSEL64               \
  " " STR_ARCH_MIPS64N32 " " STR_ARCH_MIPSEL64N32 " " STR_ARCH_PARISC         \
  " " STR_ARCH_PARISC64 " " STR_ARCH_PPC64 " " STR_ARCH_PPC                   \
  " " STR_ARCH_PPC64LE " " STR_ARCH_S390X " " STR_ARCH_S390                   \
  " " STR_ARCH_RISCV64
#define INVALID_SYSNR "Invalid syscall nr"
#define INVALID_SYS_ARGS "Invalid syscall args"
#define INVALID_IP "Invalid instruction pointer"
#define INVALID_PID "Invalid pid"
#define INPUT_SYS_NR "Please input syscall_nr to emu"

// text->raw err
#define INVALID_OPERATOR "Invalid operator"
#define INVALID_CMPENUM "Invalid cmp sym enum"
#define INVALID_ALUENUM "Invalid alu sym enum"

#define INVALID_RIGHT_VAL "Invalid right value"
#define INVALID_LEFT_VAR "Invalid left valiable"

#define INVALID_MEM_IDX "Invalid idx of $mem"
#define INVALID_MEM "Invalid $mem[]"

#define INVALID_IF "Invalid if line"
#define INVALID_RET "Invalid ret line"
#define RET_DATA_PAREN "Missing parentheses in ret data, example: ERRNO(2)"
#define INVALID_RET_DATA "Invalid ret data"

#define PAREN_WRAP_CONDITION "Use (condition) to wrap condition"
#define GOTO_AFTER_CONDITION "Use 'goto' after (condition)"
#define LINE_NR_AFTER_GOTO "Line number to go after 'goto'"
#define LINE_NR_AFTER_ELSE "Line number to go after ',else goto'"
#define INVALID_NR_AFTER_GOTO "Invalid number after goto"
#define INVALID_JMP_NR "Invalid jmp line number"

#define INVALID_ASM_CODE "Invalid asm code"

#define INVALID_RET_VAL "Invalid ret value"

// raw
#define INVALID_OFFSET_ABS "Invalid offset of seccomp_data"

#define INVALID_CLASS "Invalid class"

#define INVALID_REG_A_VAL "Invalid reg A val"
#define INVALID_REG_X_VAL "Invalid reg X val"
#define INVALID_REG_MEM_VAL(idx) "Invalid reg mem" idx "val"
#define INVALID_A_STATUS "Invalid A status"

#define INVALID_MISC_MODE "Invalid misc mode"
#define INVALID_RET_MODE "Invalid ret mode"
#define INVALID_JMP_MODE "Invalid jmp mode"
#define INVALID_JMP_SRC "Invalid jmp src"
#define INVALID_ALU_OP "Invalid alu operation"
#define INVALID_ALU_SRC "Invalid alu src"
#define ST_MEM_BEFORE_LD "Store mem before ld or ldx"

#define JT_JF_BOTH_ZERO "Jt and jf both 0"

// seccomp check err
#define ALU_DIV_BY_ZERO "Alu div by zero"
#define ALU_SH_OUT_OF_RANGE "Alu lsh or rsh out of range"
#define JMP_OUT_OF_RANGE "Jmp out of bpf len"
#define MUST_END_WITH_RET "Bpf filter must end with return"
#define INVALID_OPERTION "Invalid opertion"

#define ERROR_HAPPEN                                                          \
  "The above code has errors, please check the warnings for specific details"

// trace err
#define SYS_ADMIN_OR_KERNEL                                                   \
  "Run with CAP_SYS_ADMIN capability when trace pid\nand kernel pid can't "   \
  "be trace"
#define NO_SUCH_PROCESS "No such process with pid %d in the system"
#define NOT_AN_CBPF "Non-cbpf found, can't resolve, but continue"
#define PTRACE_SEIZE_ERR "ptrace seize error"
#define PTRACE_GET_FILTER_ERR "ptrace get filter error"
#define EXECV_ERR "execv failed executing"
#define SHOULD_BE_EXIT "should be ptrace exit here"
#define TRACE_PID_UNSUPPORTED                                                 \
  "Sorry, PTRACE_SECCOMP_GET_FILTER is not supported on your system"
#define TRACE_PID_ENOENT                                                      \
  "ENOENT returned, which is unexpected, please submit your case in our "     \
  "issues"

#endif
