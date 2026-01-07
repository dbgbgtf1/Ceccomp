#ifndef ERROR
#define ERROR

#include "i18n.h"

// probe
#define PROBE_TERMINATED _ ("Probe terminated")

// emu
#define EMU_TERMINATED _ ("Emu terminated")
#define INPUT_SYS_NR _ ("Please input syscall_nr to emu")
#define INVALID_SYSNR _ ("Invalid syscall_nr")

// asm
#define ASM_TERMINATED _ ("Asm terminated")

// disasm
#define DISASM_TERMINATED _ ("Disasm terminated")

// trace
#define PEEKDATA_FAILED_ADR _ ("Peekdata failed at %p")
#define EXECV_ERR _ ("execv failed executing")
#define PROCESS_FORK _ ("Process %d spawned a new pid %d")
#define PROCESS_EXIT _ ("Process %d exited")
#define PARSE_PID_BPF _ ("Parsing %d process seccomp filter")
#define PROCFS_NOT_ACCESSIBLE _ ("Procfs not accessible, unable to perform")
#define NOT_AN_CBPF _ ("Non-cbpf found, can't resolve, but continue")
#define SEIZING_KERNEL_THREAD _ ("Kernel thread can not be seized")
#define ACTION_PTRACE_SEIZE "ptrace seizing"
#define NO_FILTER_FOUND _ ("No seccomp filters found in pid %d\n")
#define TARGET_TRACED_BY _ ("Target process is being traced by %d pid process")
// no translation due to terms
#define ACTION_GET_FILTER "ptrace get seccomp filters"

#define CAP_SYS_PTRACE_OR_KTHREAD                                             \
  _ ("perhaps seizing kthread or lacking CAP_SYS_PTRACE")
#define REQUIRE_CAP_SYS_ADMIN                                                 \
  _ ("Run with CAP_SYS_ADMIN capability to fetch seccomp filters")
#define REQUIRE_CAP_SYS_PTRACE                                                \
  _ ("Run with CAP_SYS_PTRACE capability to seize a foreign process")
#define CANNOT_WORK_FROM_32_TO_64                                             \
  _ ("Ptrace from 32-bit tracer to 64-bit tracee is limited")
#define TRACEE_ARCH_NOT_SUPPORTED                                             \
  _ ("libseccomp does not support the tracee's arch (%#x)")
#define CAP_SYS_ADMIN_OR_IN_SECCOMP                                           \
  _ ("perhaps lacking CAP_SYS_ADMIN or ceccomp is in seccomp mode")
#define GET_FILTER_UNSUPPORTED                                                \
  _ ("PTRACE_GET_SECCOMP_FILTER is not supported on your system")
#define CECCOMP_IN_SECCOMP                                                    \
  _ ("Ceccomp is in seccomp mode, fetch seccomp filters of other process is " \
     "not permitted")
#define GET_FILTER_UNSUPPORTED_OR_NO_FILTER                                   \
  _ ("perhaps PTRACE_GET_SECCOMP_FILTER is not supported or no seccomp "      \
     "filter in target process")

// parse_args
#define INVALID_COLOR_MODE _ ("Invalid color mode")
#define INVALID_FMT_MODE _ ("Invalid format mode")
#define INVALID_NUMBER _ ("Invalid number")
#define UNABLE_OPEN_FILE _ ("Unable open file")

// read_source
#define FOUND_SUS_ZERO                                                        \
  _ ("Found '\\0' file offset %lu, perhaps it's not a text file?")
#define FOUND_SUS_NO_LF                                                       \
  _ ("No line break in source file, perhaps it's not a text file?")
#define FOUND_SUS_LINE                                                        \
  _ ("Line %u has more than %u bytes, perhaps the input is not a text file?")
#define FILE_TOO_LARGE _ ("The input file is greater than 1 MiB!")

// hash
#define CANNOT_FIND_LABEL _ ("Can not find label: %.*s")

// parser
#define UNEXPECT_TOKEN _ ("Unexpect token")

#define EXPECT_OPERATOR _ ("Expect operator")
#define EXPECT_RIGHT_VAR _ ("Expect right variable")
#define EXPECT_RETURN_VAL _ ("Expect return value")

#define EXPECT_NUMBER _ ("Expect number")
#define EXPECT_PAREN _ ("Expect paren")
#define EXPECT_BRACKET _ ("Expect bracket")
#define EXPECT_COMPARTOR _ ("Expect comparator")
#define EXPECT_LABEL _ ("Expect label")
#define EXPECT_SYSCALL _ ("Expect syscall")
#define EXPECT_ARCH _ ("Expect architecture")
// EXPECT_SYSCALL also use in resolver

#define EXPECT_GOTO _ ("Expect 'goto'")
#define EXPECT_A _ ("Expect '$A'")
#define EXPECT_ELSE _ ("Expect 'else'")
#define EXPECT_COMMA _ ("Expect ','")
#define EXPECT_NEWLINE _ ("Expect '\n'")

// resolver and check_prog
#define RIGHT_SHOULD_BE_A _ ("Right operand should be '$A'")
#define RIGHT_CAN_NOT_BE_A _ ("Right operand can not be '$A'")
#define RIGHT_CAN_NOT_BE_X _ ("Right operand can not be '$X'")

#define RIGHT_SHOULD_BE_A_OR_X _ ("Right operand should be '$A' or '$X'")
#define RIGHT_SHOULD_BE_X_OR_NUM _ ("Right operand should be '$X' or num")
#define OPERATOR_SHOULD_BE_EQUAL _ ("Operator should be '='")
#define LEFT_SHOULD_BE_A _ ("Left operand should be A")
#define INVALID_ATTR_LOAD _ ("Invalid attribute load")

#define ARGS_IDX_OUT_OF_RANGE _ ("Args index out of range")
#define MEM_IDX_OUT_OF_RANGE _ ("Mem index out of range")
#define UNINITIALIZED_MEM _ ("Uninitialized mem")
#define ALU_DIV_BY_ZERO _ ("Alu div by zero")
#define ALU_SH_OUT_OF_RANGE _ ("Alu lsh or rsh out of range")

#define RET_DATA_OVERFLOW _ ("Ret data too large")
#define JT_TOO_FAR _ ("Jt is too far")
#define JT_MUST_BE_POSITIVE _ ("Jt must be positive")
#define JF_TOO_FAR _ ("Jf is too far")
#define JF_MUST_BE_POSITIVE _ ("Jf must be positive")
#define JT_INVALID_TAG _ ("Jt to invalid tag")
#define JF_INVALID_TAG _ ("Jf to invalid tag")

#define MUST_END_WITH_RET _ ("Bpf filter must end with return")

#define INVALID_OPERATION _ ("Invalid operation")

#endif
