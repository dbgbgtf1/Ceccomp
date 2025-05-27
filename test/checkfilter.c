#include "main.h"
#include <stdbool.h>
#include <stdint.h>

int
seccomp_check_filter (filter *f_ptr, unsigned int len)
{
  for (uint32_t pc = 0; pc < len; pc++)
    {
      filter *ftest = &f_ptr[pc];
      uint16_t code = ftest->code;
      uint32_t k = ftest->k;

      switch (code)
        {
        case BPF_LD | BPF_W | BPF_ABS:
          ftest->code = BPF_LDX | BPF_W | BPF_ABS;
          if (k >= sizeof (struct seccomp_data) || k & 3)
            return -1;
          continue;
        case BPF_LD | BPF_W | BPF_LEN:
          ftest->code = BPF_LD | BPF_IMM;
          ftest->k = sizeof (struct seccomp_data);
          continue;
        case BPF_LDX | BPF_W | BPF_LEN:
          ftest->code = BPF_LDX | BPF_IMM;
          ftest->k = sizeof (struct seccomp_data);
          continue;
        /* Explicitly include allowed calls. */
        case BPF_RET | BPF_K:
        case BPF_RET | BPF_A:
        case BPF_ALU | BPF_ADD | BPF_K:
        case BPF_ALU | BPF_ADD | BPF_X:
        case BPF_ALU | BPF_SUB | BPF_K:
        case BPF_ALU | BPF_SUB | BPF_X:
        case BPF_ALU | BPF_MUL | BPF_K:
        case BPF_ALU | BPF_MUL | BPF_X:
        case BPF_ALU | BPF_DIV | BPF_K:
        case BPF_ALU | BPF_DIV | BPF_X:
        case BPF_ALU | BPF_AND | BPF_K:
        case BPF_ALU | BPF_AND | BPF_X:
        case BPF_ALU | BPF_OR | BPF_K:
        case BPF_ALU | BPF_OR | BPF_X:
        case BPF_ALU | BPF_XOR | BPF_K:
        case BPF_ALU | BPF_XOR | BPF_X:
        case BPF_ALU | BPF_LSH | BPF_K:
        case BPF_ALU | BPF_LSH | BPF_X:
        case BPF_ALU | BPF_RSH | BPF_K:
        case BPF_ALU | BPF_RSH | BPF_X:
        case BPF_ALU | BPF_NEG:
        case BPF_LD | BPF_IMM:
        case BPF_LDX | BPF_IMM:
        case BPF_MISC | BPF_TAX:
        case BPF_MISC | BPF_TXA:
        case BPF_LD | BPF_MEM:
        case BPF_LDX | BPF_MEM:
        case BPF_ST:
        case BPF_STX:
        case BPF_JMP | BPF_JA:
        case BPF_JMP | BPF_JEQ | BPF_K:
        case BPF_JMP | BPF_JEQ | BPF_X:
        case BPF_JMP | BPF_JGE | BPF_K:
        case BPF_JMP | BPF_JGE | BPF_X:
        case BPF_JMP | BPF_JGT | BPF_K:
        case BPF_JMP | BPF_JGT | BPF_X:
        case BPF_JMP | BPF_JSET | BPF_K:
        case BPF_JMP | BPF_JSET | BPF_X:
          continue;
        default:
          return -1;
        }
    }
  return 0;
}

int
bpf_check_classic (const struct sock_filter *filter, unsigned int len)
{
  bool anc_found;

  /* Check the filter code now */
  for (uint32_t pc = 0; pc < len; pc++)
    {
      const struct sock_filter *ftest = &filter[pc];

      /* May we actually operate on this code? */
      if (!chk_code_allowed (ftest->code))
        return -1;

      /* Some instructions need special checks */
      switch (ftest->code)
        {
        case BPF_ALU | BPF_DIV | BPF_K:
        case BPF_ALU | BPF_MOD | BPF_K:
          /* Check for division by zero */
          if (ftest->k == 0)
            return -1;
          break;
        case BPF_ALU | BPF_LSH | BPF_K:
        case BPF_ALU | BPF_RSH | BPF_K:
          if (ftest->k >= 32)
            return -1;
          break;
        case BPF_LD | BPF_MEM:
        case BPF_LDX | BPF_MEM:
        case BPF_ST:
        case BPF_STX:
          /* Check for invalid memory addresses */
          if (ftest->k >= BPF_MEMWORDS)
            return -1;
          break;
        case BPF_JMP | BPF_JA:
          /* Note, the large ftest->k might cause loops.
           * Compare this with conditional jumps below,
           * where offsets are limited. --ANK (981016)
           */
          if (ftest->k >= (unsigned int)(len - pc - 1))
            return -1;
          break;
        case BPF_JMP | BPF_JEQ | BPF_K:
        case BPF_JMP | BPF_JEQ | BPF_X:
        case BPF_JMP | BPF_JGE | BPF_K:
        case BPF_JMP | BPF_JGE | BPF_X:
        case BPF_JMP | BPF_JGT | BPF_K:
        case BPF_JMP | BPF_JGT | BPF_X:
        case BPF_JMP | BPF_JSET | BPF_K:
        case BPF_JMP | BPF_JSET | BPF_X:
          /* Both conditionals must be safe */
          if (pc + ftest->jt + 1 >= len || pc + ftest->jf + 1 >= len)
            return -1;
          break;
        case BPF_LD | BPF_W | BPF_ABS:
        case BPF_LD | BPF_H | BPF_ABS:
        case BPF_LD | BPF_B | BPF_ABS:
          anc_found = false;
          if (bpf_anc_helper (ftest) & BPF_ANC)
            anc_found = true;
          /* Ancillary operation unknown or unsupported */
          if (anc_found == false && ftest->k >= SKF_AD_OFF)
            return -1;
        }
    }

  /* Last instruction must be a RET code */
  switch (filter[len - 1].code)
    {
    case BPF_RET | BPF_K:
    case BPF_RET | BPF_A:
      return check_load_and_stores (filter, len);
    }

  return -1;
}
