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

// text->raw err
#define INVALID_OPERATOR _ ("Invalid operator")
#define INPOSSIBLE_CMP_ENUM _ ("Impossible cmp sym enum")
#define INPOSSIBLE_ALU_ENUM _ ("Impossible alu sym enum")

#define INVALID_RIGHT_VAL _ ("Invalid right value")
#define INVALID_LEFT_VAR _ ("Invalid left valiable")

#define INVALID_MEM_IDX _ ("Invalid idx of $mem")
#define INVALID_MEM _ ("Invalid mem statement")

#define INVALID_IF _ ("Invalid if line")
#define INVALID_RET _ ("Invalid return line")
#define RET_DATA_PAREN                                                        \
  _ ("Missing parentheses in return data, example: ERRNO(2)")
#define INVALID_RET_DATA _ ("Invalid return data")

#define PAREN_WRAP_CONDITION                                                  \
  _ ("Use parentheses to wrap condition, example: (condition)")
#define GOTO_AFTER_CONDITION _ ("Use 'goto' after (condition)")

#define LINE_NR_AFTER_GOTO _ ("Line number to go after 'goto'")
#define LINE_NR_AFTER_ELSE _ ("Line number to go after ',else goto'")
#define INVALID_NR_AFTER_GOTO _ ("Invalid line number after goto")
#define INVALID_JMP_NR _ ("Invalid jmp line number")
#define JMP_NR_LESS_THAN_PC _ ("Jmp line number less than pc")
#define INVALID_ASM_CODE _ ("Invalid asm code")
#define INVALID_RET_VAL _ ("Invalid return value")

#define LINE_TOO_LONG _ ("Line length exceeds 0x400, which shouldn't happen")

// raw
#define INVALID_OFFSET_ABS _ ("Invalid offset of seccomp_data")
#define ST_MEM_BEFORE_LD _ ("Store mem before ld or ldx")
#define JT_JF_BOTH_ZERO _ ("Jt and jf both 0")

// seccomp check err
#define ALU_DIV_BY_ZERO _ ("Alu div by zero")
#define ALU_SH_OUT_OF_RANGE _ ("Alu lsh or rsh out of range")
#define JMP_OUT_OF_RANGE _ ("Jmp out of bpf len")
#define MUST_END_WITH_RET _ ("Bpf filter must end with return")
#define INVALID_OPERTION _ ("Invalid opertion")

#define ERROR_HAPPEN                                                          \
  _ ("The above code has errors, please check the warnings for specific "     \
     "details")

// trace err
// trace execv
#define EXECV_ERR _ ("execv failed executing")
#define SHOULD_BE_EXIT _ ("tracee syscall should be exiting here")
#define PROCESS_FORK _ ("Process %d spawned a new pid %d")
#define PROCESS_EXIT _ ("Process %d exited")
#define PARSE_PID_BPF _ ("Parsing %d process seccomp filter")
#define PEEKDATA_FAILED_ADR _ ("Peekdata failed in address: %p")
#define CANNOT_WORK_FROM_32_TO_64                                             \
  _ ("Ptrace from 32-bit tracer to 64-bit tracee is limited")

// trace pid
#define PROCFS_NOT_ACCESSIBLE _ ("Procfs not accessible, unable to perform")
#define TARGET_TRACED_BY _ ("Target process is being traced by %d pid process")
// no translation due to terms
#define ACTION_PTRACE_SEIZE "ptrace seizing"
#define REQUIRE_CAP_SYS_PTRACE                                                \
  _ ("Run with CAP_SYS_PTRACE capability to seize a foreign process")
#define SEIZING_KERNEL_THREAD _ ("Kernel thread can not be seized")
#define CAP_SYS_PTRACE_OR_KTHREAD                                             \
  _ ("perhaps seizing kthread or lacking CAP_SYS_PTRACE")
#define NO_SUCH_PROCESS _ ("No such process with pid %d in the system")
#define NOT_AN_CBPF _ ("Non-cbpf found, can't resolve, but continue")

// no translation due to terms
#define ACTION_GET_FILTER "ptrace get seccomp filters"
#define GET_FILTER_UNSUPPORTED_OR_NO_FILTER                                   \
  _ ("perhaps PTRACE_GET_SECCOMP_FILTER is not supported or no seccomp "      \
     "filter "                                                                \
     "in target process")
#define GET_FILTER_UNSUPPORTED                                                \
  _ ("PTRACE_GET_SECCOMP_FILTER is not supported on your system")
#define POSSIBLE_ERRORS _ ("Error cause unknown, due to the followings")
#define CECCOMP_IN_SECCOMP                                                    \
  _ ("Ceccomp is in seccomp mode, fetch seccomp filters of other process is " \
     "not permitted")

#define REQUIRE_CAP_SYS_ADMIN                                                 \
  _ ("Run with CAP_SYS_ADMIN capability to fetch seccomp filters")
#define CAP_SYS_ADMIN_OR_IN_SECCOMP                                           \
  _ ("perhaps lacking CAP_SYS_ADMIN or ceccomp is in seccomp mode")

#define NO_FILTER_FOUND _ ("No seccomp filters found in pid %d\n")

#endif
