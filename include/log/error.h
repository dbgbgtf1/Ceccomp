#ifndef ERROR
#define ERROR

#include "i18n.h"

// emu
#define EMU_TERMINATED _ ("Emu terminated")
#define INPUT_SYS_NR _ ("Please input syscall_nr to emu")
#define INVALID_SYSNR _ ("Invalid syscall_nr")

// asm
#define ASM_TERMINATED _ ("Asm terminated")

// disasm
#define DISASM_TERMINATED _ ("Disasm terminated")

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

#define JT_TOO_FAR _ ("Jt is too far")
#define JF_TOO_FAR _ ("Jf is too far")

#define MUST_END_WITH_RET _ ("Bpf filter must end with return")

#define INVALID_OPERATION _ ("Invalid operation")

#endif
