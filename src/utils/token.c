#include "token.h"
#include "log/logger.h"
#include "scanner.h"
#include <stddef.h>

// clang-format off
char *token_pairs[] = {
  [ARCH_X86] = "i386", [ARCH_I686] = "i686", [ARCH_X86_64] = "x86_64",
  [ARCH_X32] = "x32", [ARCH_ARM] = "arm", [ARCH_AARCH64] = "aarch64",
  [ARCH_LONNGARCH64] = "loongarch64", [ARCH_M68K] = "m68k", [ARCH_MIPSEL64N32] = "mipsel64n32",
  [ARCH_MIPSEL64] = "mipsel64", [ARCH_MIPSEL] = "mipsel", [ARCH_MIPS64N32] = "mips64n32", 
  [ARCH_MIPS64] = "mips64", [ARCH_MIPS] = "mips", [ARCH_PARISC64] = "parisc64",
  [ARCH_PARISC] = "parisc", [ARCH_PPC64LE] = "ppc64le", [ARCH_PPC64] = "ppc64",
  [ARCH_PPC] = "ppc64", [ARCH_S390X] = "s390x", [ARCH_S390] = "s390",
  [ARCH_RISCV64] = "riscv64",

  [KILL_PROC] = "KILL_PROCESS", [KILL] = "KILL", [ALLOW] = "ALLOW", [NOTIFY] = "NOTIFY",
  [LOG] = "LOG", [TRAP] = "TRAP", [ERRNO] = "ERRNO", [TRACE] = "TRACE",

  [A] = "$A", [X] = "$X", [MEM] = "$mem",
  [VAR_SYSCALL] = "$syscall_nr", [VAR_ARCH] = "$arch", [VAR_LOWPC] = "$low_pc",
  [VAR_HIGHPC] = "$high_pc", [VAR_LOWARG] = "$low_arg", [VAR_HIGHARG] = "$high_arg",

  [RETURN] = "return", [IF] = "if", [GOTO] = "goto", [COMMA] = ",", [ELSE] = "else",

  [LEFT_BRACKET] = "[", [RIGHT_BRACKET] = "]",
  [LEFT_PAREN] = "(", [RIGHT_PAREN] = ")",
  [EQUAL] = "=", [EQUAL_EQUAL] = "==",
  [BANG] = "!", [BANG_EQUAL] = "!=",
  [GREATER_THAN] = ">", [GREATER_EQUAL] = ">=",
  [LESS_THAN] = "<", [LESS_EQUAL] = "<=",
  [ADD_TO] = "+=", [SUB_TO] = "-=", [MULTI_TO] = "*=", [DIVIDE_TO] = "/=", [AND_TO] = "&=",

  [DOT] = ".", [NEWLINE] = "\n",

  [UNKNOWN] = "unknown", [COMMENT] = "#", [TOKEN_EOF] = "EOF",
  [IDENTIFIER] = "identifier", [LABEL_DECL] = "label_decl", [NUMBER] = "number",
};
// clang-format on

token_t
init_token (scanner_t *scanner, token_type type)
{
  token_t token;
  token.type = type;
  token.token_start = scanner->token_start;
  token.token_len = scanner->current_char - scanner->token_start;
  token.line_nr = scanner->line_nr;

  if (*token_pairs[type] != '\n')
    {
      debug ("At %04d: %s", token.line_nr, token_pairs[type]);
      debug ("       | %.*s\n", token.token_len, token.token_start);
    }
  else
    {
      debug ("At %04d: NEWLINE", token.line_nr);
      debug ("%s", "       | \n");
    }

  return token;
}

token_t
init_token_data (scanner_t *scanner, token_type type, size_t data)
{
  token_t token = init_token (scanner, type);
  token.data = data;
  return token;
}
