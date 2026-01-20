// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * This part of code are adapted from Linux kernel,
 * source files are: net/core/filter.c and kernel/seccomp.c
 *
 * Thanks to following authors and their commit time:
 *
 * 2012       Will Drewry <wad@chromium.org>
 * 2004-2005  Andrea Arcangeli <andrea@cpushare.com>
 * 2011-2014  PLUMgrid, http://plumgrid.com
 *            Jay Schulist <jschlst@samba.org>
 *            Alexei Starovoitov <ast@plumgrid.com>
 *            Daniel Borkmann <dborkman@redhat.com>
 *            Andi Kleen
 *            Kris Katterjohn
 */
#include "check_prog.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include "vector.h"
#include <assert.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const bool codes[] = {
  /* 32 bit ALU operations */
  [BPF_ALU | BPF_ADD | BPF_K] = true,
  [BPF_ALU | BPF_ADD | BPF_X] = true,
  [BPF_ALU | BPF_SUB | BPF_K] = true,
  [BPF_ALU | BPF_SUB | BPF_X] = true,
  [BPF_ALU | BPF_MUL | BPF_K] = true,
  [BPF_ALU | BPF_MUL | BPF_X] = true,
  [BPF_ALU | BPF_DIV | BPF_K] = true,
  [BPF_ALU | BPF_DIV | BPF_X] = true,
  [BPF_ALU | BPF_AND | BPF_K] = true,
  [BPF_ALU | BPF_AND | BPF_X] = true,
  [BPF_ALU | BPF_OR | BPF_K] = true,
  [BPF_ALU | BPF_OR | BPF_X] = true,
  [BPF_ALU | BPF_XOR | BPF_K] = true,
  [BPF_ALU | BPF_XOR | BPF_X] = true,
  [BPF_ALU | BPF_LSH | BPF_K] = true,
  [BPF_ALU | BPF_LSH | BPF_X] = true,
  [BPF_ALU | BPF_RSH | BPF_K] = true,
  [BPF_ALU | BPF_RSH | BPF_X] = true,
  [BPF_ALU | BPF_NEG] = true,
  /* Load instructions */
  [BPF_LD | BPF_W | BPF_ABS] = true,
  [BPF_LD | BPF_W | BPF_LEN] = true,
  [BPF_LD | BPF_IMM] = true,
  [BPF_LD | BPF_MEM] = true,
  [BPF_LDX | BPF_W | BPF_LEN] = true,
  [BPF_LDX | BPF_IMM] = true,
  [BPF_LDX | BPF_MEM] = true,
  /* Store instructions */
  [BPF_ST] = true,
  [BPF_STX] = true,
  /* Misc instructions */
  [BPF_MISC | BPF_TAX] = true,
  [BPF_MISC | BPF_TXA] = true,
  /* Return instructions */
  [BPF_RET | BPF_K] = true,
  [BPF_RET | BPF_A] = true,
  /* Jump instructions */
  [BPF_JMP | BPF_JA] = true,
  [BPF_JMP | BPF_JEQ | BPF_K] = true,
  [BPF_JMP | BPF_JEQ | BPF_X] = true,
  [BPF_JMP | BPF_JGE | BPF_K] = true,
  [BPF_JMP | BPF_JGE | BPF_X] = true,
  [BPF_JMP | BPF_JGT | BPF_K] = true,
  [BPF_JMP | BPF_JGT | BPF_X] = true,
  [BPF_JMP | BPF_JSET | BPF_K] = true,
  [BPF_JMP | BPF_JSET | BPF_X] = true,
};

static uint16_t *masks, mem_valid = 0;

typedef enum
{
  CODE_ERR,
  JT_ERR,
  JF_ERR,
  K_ERR,
  NONE,
} err_idx;

uint32_t err_len[] = {
  [CODE_ERR] = 0,
  [JT_ERR] = LITERAL_STRLEN ("CODE:0x1234 "),
  [JF_ERR] = LITERAL_STRLEN ("CODE:0x1234 JT:0x56"),
  [K_ERR] = LITERAL_STRLEN ("CODE:0x1234 JF:0x56 JT:0x78 "),
  [NONE] = LITERAL_STRLEN ("CODE:0x1234 JF:0x56 JF:0x78 K:0x9abcdef0"),
};

#define SPRINTF_CAT(...) print += sprintf (print, __VA_ARGS__)
static bool
report_error (filter f, err_idx idx, const char *err_msg)
{
  char buf[0x400];
  char *print = buf;

  SPRINTF_CAT ("%s\nCODE:0x%04x JT:0x%02x JF:0x%02x K:0x%08x\n", err_msg,
               f.code, f.jt, f.jf, f.k);
  if (idx == NONE)
    memset (print, '~', err_len[NONE]);
  else
    {
      memset (print, ' ', err_len[idx]);
      print[err_len[idx]] = '^';
      print[err_len[idx] + 1] = '\0';
    }
  warn ("%s", buf);

  return true;
}

// return true if error
static bool
check_filter (filter *fptr, uint32_t pc, uint32_t flen)
{
  filter f = fptr[pc];
  uint16_t code = f.code;
  uint32_t k = f.k;

  if (code >= ARRAY_SIZE (codes) || !codes[code])
    error ("%s", M_INVALID_OPERATION);

  switch (code)
    {
    case BPF_LD | BPF_W | BPF_ABS:
      f.code = BPF_LDX | BPF_W | BPF_ABS;
      if (k >= sizeof (struct seccomp_data) || k & 3)
        return report_error (f, K_ERR, M_INVALID_ATTR_LOAD);
      return false;

    case BPF_LD | BPF_W | BPF_LEN:
      f.code = BPF_LD | BPF_IMM;
      f.k = sizeof (struct seccomp_data);
      return false;

    case BPF_LDX | BPF_W | BPF_LEN:
      f.code = BPF_LDX | BPF_IMM;
      f.k = sizeof (struct seccomp_data);
      return false;

    case BPF_ALU | BPF_DIV | BPF_K:
      if (f.k == 0)
        return report_error (f, K_ERR, M_ALU_DIV_BY_ZERO);
      return false;

    case BPF_ALU | BPF_LSH | BPF_K:
    case BPF_ALU | BPF_RSH | BPF_K:
      if (f.k >= 32)
        return report_error (f, K_ERR, M_ALU_SH_OUT_OF_RANGE);
      return false;

    case BPF_LD | BPF_MEM:
    case BPF_LDX | BPF_MEM:
      if (f.k >= BPF_MEMWORDS)
        return report_error (f, K_ERR, M_MEM_IDX_OUT_OF_RANGE);
      if (!(mem_valid & (1 << fptr[pc].k)))
        return report_error (f, NONE, M_UNINITIALIZED_MEM);
      return false;

    case BPF_ST:
    case BPF_STX:
      if (f.k >= BPF_MEMWORDS)
        return report_error (f, K_ERR, M_MEM_IDX_OUT_OF_RANGE);
      mem_valid |= (1 << fptr[pc].k);
      return false;

    case BPF_JMP | BPF_JA:
      if (f.k >= (uint32_t)(flen - pc - 1))
        return report_error (f, K_ERR, M_JT_TOO_FAR);
      masks[pc + 1 + fptr[pc].k] &= mem_valid;
      mem_valid = ~0;
      return false;

    case BPF_JMP | BPF_JEQ | BPF_K:
    case BPF_JMP | BPF_JEQ | BPF_X:
    case BPF_JMP | BPF_JGE | BPF_K:
    case BPF_JMP | BPF_JGE | BPF_X:
    case BPF_JMP | BPF_JGT | BPF_K:
    case BPF_JMP | BPF_JGT | BPF_X:
    case BPF_JMP | BPF_JSET | BPF_K:
    case BPF_JMP | BPF_JSET | BPF_X:
      if (pc + f.jt + 1 >= flen)
        return report_error (f, JT_ERR, M_JT_TOO_FAR);
      if (pc + f.jf + 1 >= flen)
        return report_error (f, JF_ERR, M_JF_TOO_FAR);
      masks[pc + 1 + fptr[pc].jt] &= mem_valid;
      masks[pc + 1 + fptr[pc].jf] &= mem_valid;
      mem_valid = ~0;
      return false;
    }
  return false;
}

bool
check_prog (fprog *prog)
{
  bool err = true;
  masks = reallocate (NULL, sizeof (*masks) * prog->len);
  memset (masks, 0xff, sizeof (*masks) * prog->len);
  mem_valid = 0;

  for (uint16_t i = 0; i < prog->len; i++)
    {

      if (check_filter (prog->filter, i, prog->len))
        goto complete;
    }

  filter last = prog->filter[prog->len - 1];
  uint16_t last_code = last.code;
  if ((last_code != (BPF_RET | BPF_A)) && (last_code != (BPF_RET | BPF_K)))
    {
      report_error (last, NONE, M_MUST_END_WITH_RET);
      goto complete;
    }

  err = false;

complete:
  reallocate (masks, 0x0);
  return err;
}
