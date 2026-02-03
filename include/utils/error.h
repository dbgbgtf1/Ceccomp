#ifndef ERROR_H
#define ERROR_H

#include "i18n.h"

// probe
#define M_PROBE_TERMINATED _ ("Probe terminated")

// emu
#define M_EMU_TERMINATED _ ("Emu terminated")
#define M_INPUT_SYS_NR _ ("Please input syscall_nr to emu")
#define M_INVALID_SYSNR _ ("Invalid syscall_nr")

// asm
#define M_ASM_TERMINATED _ ("Asm terminated")

// disasm
#define M_DISASM_TERMINATED _ ("Disasm terminated")
#define M_NO_FILTER _ ("The input is empty")
#define M_TOO_LARGE_INPUT                                                     \
  _ ("The input is larger than 1024 filters! Perhaps inputting a wrong "      \
     "file?")
#define M_INPUT_HAS_LEFTOVER                                                  \
  _ ("%d byte(s) at the end of input could not fit into a filter")

// trace
#define M_ATTACHING_ON _ ("Attaching on process %d")
#define M_PEEKDATA_FAILED_ADR _ ("Peekdata failed at %p")
#define M_EXECV_ERR _ ("execv failed executing")
#define M_PROCESS_FORK _ ("Process %d spawned a new pid %d")
#define M_PROCESS_EXIT _ ("Process %d exited")
#define M_PARSE_PID_BPF _ ("Parsing %d process seccomp filter")
#define M_PID_BPF_LOAD_FAIL _ ("%d process load seccomp filter failed")
#define M_PROCFS_NOT_ACCESSIBLE _ ("Procfs not accessible, unable to perform")
#define M_NOT_AN_CBPF _ ("Non-cbpf found, can't resolve, but continue")
#define M_SEIZING_KERNEL_THREAD _ ("Kernel thread can not be seized")
#define M_NO_FILTER_FOUND _ ("No seccomp filters found in pid %d\n")
#define M_TARGET_TRACED_BY                                                    \
  _ ("Target process is being traced by %d pid process")
#define M_FOUND_STRICT_MODE                                                   \
  _ ("Process %d loaded strict seccomp mode, which only allows read, "        \
     "write, exit_group and sigreturn!")
// no translation due to terms
#define ACTION_GET_FILTER "ptrace get seccomp filters"
#define ACTION_PTRACE_SEIZE "ptrace seizing"

#define M_CAP_SYS_PTRACE_OR_KTHREAD                                           \
  _ ("perhaps seizing kthread or lacking CAP_SYS_PTRACE")
#define M_REQUIRE_CAP_SYS_ADMIN                                               \
  _ ("Run with CAP_SYS_ADMIN capability to fetch seccomp filters")
#define M_REQUIRE_CAP_SYS_PTRACE                                              \
  _ ("Run with CAP_SYS_PTRACE capability to seize a foreign process")
#define M_CANNOT_WORK_FROM_32_TO_64                                           \
  _ ("Ptrace from 32-bit tracer to 64-bit tracee is limited")
#define M_TRACEE_ARCH_NOT_SUPPORTED                                           \
  _ ("libseccomp does not support the tracee's arch (%#x)")
#define M_CAP_SYS_ADMIN_OR_IN_SECCOMP                                         \
  _ ("perhaps lacking CAP_SYS_ADMIN or ceccomp is in seccomp mode")
#define M_GET_FILTER_UNSUPPORTED                                              \
  _ ("PTRACE_GET_SECCOMP_FILTER is not supported on your system")
#define M_CECCOMP_IN_SECCOMP                                                  \
  _ ("Ceccomp is in seccomp mode, fetch seccomp filters of other process is " \
     "not permitted")
#define M_GET_FILTER_UNSUPPORTED_OR_NO_FILTER                                 \
  _ ("perhaps PTRACE_GET_SECCOMP_FILTER is not supported or no seccomp "      \
     "filter in target process")

// parse_args
#define M_INVALID_COLOR_MODE _ ("Invalid color mode")
#define M_INVALID_FMT_MODE _ ("Invalid format mode")
#define M_INVALID_NUMBER _ ("Invalid number")
#define M_UNABLE_OPEN_FILE _ ("Unable open file")

// read_source
#define M_FOUND_SUS_ZERO                                                      \
  _ ("Found '\\0' at file offset %lu, perhaps it's not a text file?")
#define M_FOUND_SUS_NO_LF                                                     \
  _ ("No line break in source file, perhaps it's not a text file?")
#define M_FOUND_SUS_LINE                                                      \
  _ ("Line %u has more than %u bytes, perhaps the input is not a text file?")
#define M_FILE_TOO_LARGE _ ("The input file is greater than 1 MiB!")
#define M_LINES_TOO_MANY                                                      \
  _ ("Found more than 4096 lines of text, perhaps it's not for ceccomp?")

// hash
#define M_CANNOT_FIND_LABEL _ ("Can not find label")

// parser
#define M_UNEXPECT_TOKEN _ ("Unexpect token")
#define M_DUPLICATED_LABEL _ ("Found duplicated label declaration")

#define M_EXPECT_OPERATOR _ ("Expect operator")
#define M_EXPECT_RIGHT_VAR _ ("Expect right variable")
#define M_EXPECT_RETURN_VAL _ ("Expect return value")

#define M_EXPECT_NUMBER _ ("Expect number")
#define M_EXPECT_PAREN _ ("Expect paren")
#define M_EXPECT_BRACKET _ ("Expect bracket")
#define M_EXPECT_COMPARTOR _ ("Expect comparator")
#define M_EXPECT_LABEL _ ("Expect label")
#define M_EXPECT_SYSCALL _ ("Expect syscall")
#define M_EXPECT_ARCH _ ("Expect architecture")
// EXPECT_SYSCALL also use in resolver

#define M_EXPECT_GOTO _ ("Expect 'goto'")
#define M_EXPECT_A _ ("Expect '$A'")
#define M_EXPECT_ELSE _ ("Expect 'else'")

// resolver and check_prog
#define M_RIGHT_SHOULD_BE_A _ ("Right operand should be '$A'")
#define M_RIGHT_CAN_NOT_BE_A _ ("Right operand can not be '$A'")
#define M_RIGHT_CAN_NOT_BE_X _ ("Right operand can not be '$X'")

#define M_RIGHT_SHOULD_BE_A_OR_X _ ("Right operand should be '$A' or '$X'")
#define M_RIGHT_SHOULD_BE_X_OR_NUM _ ("Right operand should be '$X' or num")
#define M_OPERATOR_SHOULD_BE_EQUAL _ ("Operator should be '='")
#define M_LEFT_SHOULD_BE_A _ ("Left operand should be A")
#define M_INVALID_ATTR_LOAD _ ("Invalid attribute load")

#define M_ARGS_IDX_OUT_OF_RANGE _ ("Args index out of range")
#define M_MEM_IDX_OUT_OF_RANGE _ ("Mem index out of range")
#define M_UNINITIALIZED_MEM _ ("Uninitialized mem")
#define M_ALU_DIV_BY_ZERO _ ("Alu div by zero")
#define M_ALU_SH_OUT_OF_RANGE _ ("Alu lsh or rsh out of range")

#define M_RET_DATA_OVERFLOW _ ("Ret data too large")
#define M_JT_TOO_FAR _ ("Jt is too far")
#define M_JT_MUST_BE_POSITIVE _ ("Jt must be positive")
#define M_JF_TOO_FAR _ ("Jf is too far")
#define M_JF_MUST_BE_POSITIVE _ ("Jf must be positive")
#define M_JT_INVALID_TAG _ ("Jt to invalid tag")
#define M_JF_INVALID_TAG _ ("Jf to invalid tag")

#define M_MUST_END_WITH_RET _ ("Bpf filter must end with return")
#define M_NO_VALID_CODE _ ("Text inputed doesn't contain any valid code")

#define M_INVALID_OPERATION _ ("Invalid operation")

#endif
