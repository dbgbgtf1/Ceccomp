#ifndef ERROR
#define ERROR

#include "i18n.h"
// args err
#define UNABLE_OPEN_FILE _("Unable to open file")
#define INVALID_ARCH _("Invalid arch")
#define INVALID_PRINT_MODE _("Invalid print mode")
#define INVALID_COLOR_MODE _("Invalid color mode")
#define SUPPORT_ARCH                                                          \
  STR_ARCH_X86                                                                \
  " " STR_ARCH_X86_64 " " STR_ARCH_X32 " " STR_ARCH_ARM " " STR_ARCH_AARCH64  \
  " " STR_ARCH_LOONGARCH64 " " STR_ARCH_M68K " " STR_ARCH_MIPS                \
  " " STR_ARCH_MIPSEL " " STR_ARCH_MIPS64 " " STR_ARCH_MIPSEL64               \
  " " STR_ARCH_MIPS64N32 " " STR_ARCH_MIPSEL64N32 " " STR_ARCH_PARISC         \
  " " STR_ARCH_PARISC64 " " STR_ARCH_PPC64 " " STR_ARCH_PPC                   \
  " " STR_ARCH_PPC64LE " " STR_ARCH_S390X " " STR_ARCH_S390                   \
  " " STR_ARCH_RISCV64
#define INVALID_SYSNR _("Invalid syscall nr")
#define INVALID_SYS_ARGS _("Invalid syscall args")
#define INVALID_IP _("Invalid instruction pointer")
#define INVALID_PID _("Invalid pid")
#define INPUT_SYS_NR _("Please input syscall_nr to emu")

// text->raw err
#define INVALID_OPERATOR _("Invalid operator")
#define INPOSSIBLE_CMP_ENUM _("Inpossible cmp sym enum")
#define INPOSSIBLE_ALU_ENUM _("Inpossible alu sym enum")

#define INVALID_RIGHT_VAL _("Invalid right value")
#define INVALID_LEFT_VAR _("Invalid left valiable")

#define INVALID_MEM_IDX _("Invalid idx of $mem")
#define INVALID_MEM _("Invalid mem statement")

#define INVALID_IF _("Invalid if line")
#define INVALID_RET _("Invalid return line")
#define RET_DATA_PAREN _("Missing parentheses in return data, example: ERRNO(2)")
#define INVALID_RET_DATA _("Invalid return data")

#define PAREN_WRAP_CONDITION _("Use parentheses to wrap condition, example: (condition)")
#define GOTO_AFTER_CONDITION _("Use 'goto' after (condition)")

#define LINE_NR_AFTER_GOTO _("Line number to go after 'goto'")
#define LINE_NR_AFTER_ELSE _("Line number to go after ',else goto'")
#define INVALID_NR_AFTER_GOTO _("Invalid line number after goto")
#define INVALID_JMP_NR _("Invalid jmp line number")
#define INVALID_ASM_CODE _("Invalid asm code")
#define INVALID_RET_VAL _("Invalid return value")

// raw
#define INVALID_OFFSET_ABS _("Invalid offset of seccomp_data")
#define ST_MEM_BEFORE_LD _("Store mem before ld or ldx")
#define JT_JF_BOTH_ZERO _("Jt and jf both 0")

// seccomp check err
#define ALU_DIV_BY_ZERO _("Alu div by zero")
#define ALU_SH_OUT_OF_RANGE _("Alu lsh or rsh out of range")
#define JMP_OUT_OF_RANGE _("Jmp out of bpf len")
#define MUST_END_WITH_RET _("Bpf filter must end with return")
#define INVALID_OPERTION _("Invalid opertion")

#define ERROR_HAPPEN                                                          \
  _("The above code has errors, please check the warnings for specific details")

// trace err
#define SYS_ADMIN_OR_KERNEL                                                   \
  _("Run with CAP_SYS_ADMIN capability when trace pid\nand kernel pid can't "   \
  "be trace")
#define NO_SUCH_PROCESS _("No such process with pid %d in the system")
#define NOT_AN_CBPF _("Non-cbpf found, can't resolve, but continue")
#define EXECV_ERR _("execv failed executing")
#define SHOULD_BE_EXIT _("tracee syscall should be exiting here")
#define TRACE_PID_UNSUPPORTED                                                 \
  _ ("PTRACE_SECCOMP_GET_FILTER is not supported on your system")
#define POSSIBLE_ERRORS _ ("Error cause unknown, due to the followings")
#define TRACEE_STRICT _ ("tracee in strict mode")
#define CECCOMP_IN_SECCOMP                                                    \
  _("Ceccomp is in seccomp, kernel forbid tracer in seccomp to get tracee "     \
  "filter")
#define PROCESS_FORK _ ("Process %d spawned a new pid %d")
#define PROCESS_EXIT _ ("Process %d exited")
#define PARSE_PID_BPF _ ("Parsing %d process seccomp")

#endif
