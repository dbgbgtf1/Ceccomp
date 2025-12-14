#ifndef TOKEN
#define TOKEN

#include <stddef.h>
#include <stdint.h>
// clang-format off
// many thing rely on the enum order, careful when modify this
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

  KILL_PROC, KILL, ALLOW, NOTIFY,
  LOG, TRACE, TRAP, ERRNO,

  A, X, MEM, ATTR_LEN,
  ATTR_SYSCALL, ATTR_ARCH, ATTR_LOWPC, ATTR_HIGHPC,
  ATTR_LOWARG, ATTR_HIGHARG,

  RETURN, IF, GOTO, COMMA, ELSE,

  DOT,

  LEFT_BRACKET, RIGHT_BRACKET,
  LEFT_PAREN, RIGHT_PAREN,
  ADD_TO, SUB_TO, MULTI_TO,
  DIVIDE_TO, LSH_TO, RSH_TO,
  AND_TO, OR_TO, XOR_TO,

  EQUAL_EQUAL, BANG_EQUAL,
  GREATER_EQUAL, GREATER_THAN,
  LESS_EQUAL, LESS_THAN,
  AND, EQUAL,
  NEGATIVE, BANG,

  UNKNOWN, COMMENT, EOL, TOKEN_EOF,
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
  // data is for NUMBER
};

extern char *token_pairs[];

typedef struct scanner_t scanner_t;
typedef struct token_t token_t;

void init_token (token_t *token, scanner_t *scanner, token_type type);

void init_token_data (token_t *token, scanner_t *scanner, token_type type,
                      uint32_t data);

#endif
