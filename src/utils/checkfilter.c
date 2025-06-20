#include "checkfilter.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <stdint.h>

void
scmp_check_filter (filter *f_ptr, uint32_t len)
{
  uint32_t pc;
  for (pc = 0; pc < len - 1; pc++)
    {
      filter *ftest = &f_ptr[pc];
      set_log ("", pc + 1);
      uint16_t code = ftest->code;

      switch (code)
        {
        case BPF_LD | BPF_ABS:
        // BPF_LDX | BPF_ABS doen't belong to cBPF
        case BPF_LD | BPF_IMM:
        case BPF_LDX | BPF_IMM:
        case BPF_LD | BPF_MEM:
        case BPF_LDX | BPF_MEM:
          continue;
        case BPF_LD | BPF_LEN:
          ftest->code = BPF_LD | BPF_IMM;
          ftest->k = sizeof (struct seccomp_data);
          continue;
        case BPF_LDX | BPF_LEN:
          ftest->code = BPF_LDX | BPF_IMM;
          ftest->k = sizeof (struct seccomp_data);
          continue;
        case BPF_ST:
        case BPF_STX:
        case BPF_ALU | BPF_ADD | BPF_K:
        case BPF_ALU | BPF_ADD | BPF_X:
        case BPF_ALU | BPF_SUB | BPF_K:
        case BPF_ALU | BPF_SUB | BPF_X:
        case BPF_ALU | BPF_MUL | BPF_K:
        case BPF_ALU | BPF_MUL | BPF_X:
          continue;
        case BPF_ALU | BPF_DIV | BPF_K:
          if (ftest->k == 0)
            log_info (ALU_DIV_BY_ZERO);
          continue;
        case BPF_ALU | BPF_DIV | BPF_X:
        case BPF_ALU | BPF_AND | BPF_K:
        case BPF_ALU | BPF_AND | BPF_X:
        case BPF_ALU | BPF_OR | BPF_K:
        case BPF_ALU | BPF_OR | BPF_X:
        case BPF_ALU | BPF_XOR | BPF_K:
        case BPF_ALU | BPF_XOR | BPF_X:
          continue;
        case BPF_ALU | BPF_LSH | BPF_K:
        case BPF_ALU | BPF_RSH | BPF_K:
          if (ftest->k >= 32)
            log_err (ALU_SH_OUT_OF_RANGE);
          continue;
        case BPF_ALU | BPF_LSH | BPF_X:
        case BPF_ALU | BPF_RSH | BPF_X:
        case BPF_ALU | BPF_NEG:
        case BPF_MISC | BPF_TAX:
        case BPF_MISC | BPF_TXA:
          continue;
        case BPF_JMP | BPF_JA:
          if (ftest->k >= (unsigned int)(len - pc - 1))
            log_err (JMP_OUT_OF_RANGE);
          continue;
        case BPF_JMP | BPF_JEQ | BPF_K:
        case BPF_JMP | BPF_JEQ | BPF_X:
        case BPF_JMP | BPF_JGE | BPF_K:
        case BPF_JMP | BPF_JGE | BPF_X:
        case BPF_JMP | BPF_JGT | BPF_K:
        case BPF_JMP | BPF_JGT | BPF_X:
        case BPF_JMP | BPF_JSET | BPF_K:
        case BPF_JMP | BPF_JSET | BPF_X:
          if (pc + ftest->jt + 1 >= len || pc + ftest->jf + 1 >= len)
            log_err (JMP_OUT_OF_RANGE);
          continue;
        case BPF_RET | BPF_K:
        case BPF_RET | BPF_A:
          continue;
        default:
          log_err (INVALID_OPERTION);
        }
    }

  switch (f_ptr[pc].code)
    {
    case BPF_RET | BPF_K:
    case BPF_RET | BPF_A:
      return;
    }

  log_err (MUST_END_WITH_RET);
}
