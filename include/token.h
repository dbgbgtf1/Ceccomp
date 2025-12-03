#ifndef TOKEN
#define TOKEN

#include <stddef.h>
#include <stdint.h>
// clang-format off
typedef enum
{
  ARCH_X86, ARCH_I686, ARCH_X86_64,
  ARCH_X32, ARCH_ARM, ARCH_AARCH64,
  ARCH_LONNGARCH64, ARCH_M68K, ARCH_MIPSEL64N32,
  ARCH_MIPSEL64, ARCH_MIPSEL, ARCH_MIPS64N32,
  ARCH_MIPS64, ARCH_MIPS, ARCH_PARISC64,
  ARCH_PARISC, ARCH_PPC64LE, ARCH_PPC64,
  ARCH_PPC, ARCH_S390X, ARCH_S390,
  ARCH_RISCV64,

  KILL_PROC, KILL, ALLOW, NOTIFY, LOG, TRAP, ERRNO, TRACE,

  A, X, MEM,
  VAR_SYSCALL, VAR_ARCH, VAR_LOWPC, VAR_HIGHPC,
  VAR_LOWARG, VAR_HIGHARG,

  RETURN, IF, GOTO, COMMA, ELSE,

  LEFT_BRACKET, RIGHT_BRACKET,
  LEFT_PAREN, RIGHT_PAREN,
  EQUAL, EQUAL_EQUAL, BANG, BANG_EQUAL,
  GREATER_THAN, GREATER_EQUAL, LESS_THAN, LESS_EQUAL,
  ADD_TO, SUB_TO, MULTI_TO, DIVIDE_TO, AND_TO,

  DOT, NEWLINE,

  UNKNOWN, COMMENT, TOKEN_EOF,
  IDENTIFIER, LABEL_DECL, NUMBER,
  // IDENTIFIER includes SYSCALL, LABEL
  // LABEL_DECL = (IDENTIFIER + ':')
} token_type;
// clang-format on

struct token_t
{
  token_type type;
  char *token_start;
  uint16_t token_len;
  uint16_t line_nr;

  uint32_t data;
};

extern char *token_pairs[];

typedef struct scanner_t scanner_t;
typedef struct token_t token_t;

token_t init_token (scanner_t *scanner, token_type type);

token_t init_token_data (scanner_t *scanner, token_type type, size_t data);

#endif
