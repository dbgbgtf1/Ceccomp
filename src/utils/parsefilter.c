#include "parsefilter.h"
#include "color.h"
#include "emu.h"
#include "error.h"
#include "main.h"
#include "parseargs.h"
#include "transfer.h"
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REG_BUF_LEN 0x100

static fprog *prog;
static uint32_t arch;

static char A[REG_BUF_LEN] = "0";
static char X[REG_BUF_LEN] = "0";
static char mem[0x10][REG_BUF_LEN] = { "0" };

typedef enum
{
  architecture = 0,
  syscall_nr = 1,
  none = 2,
} reg_status;

static reg_status A_status = none;
static reg_status X_status = none;

static char *
load_reg (char reg[REG_BUF_LEN], reg_status *reg_stat, filter *f_ptr)
{
  uint16_t mode = BPF_MODE (f_ptr->code);
  uint32_t k = f_ptr->k;
  char *abs_name = 0;

  switch (mode)
    {
    case BPF_IMM:
      snprintf (reg, REG_BUF_LEN, "0x%x", f_ptr->k);
      return reg;
    case BPF_ABS:
      abs_name = ABS2STR (k);
      if (!abs_name)
        PEXIT (INVALID_OFFSET_ABS ": " BLUE_H, k);
      strcpy (reg, abs_name);
      if (!strcmp (reg, ARCHITECTURE))
        *reg_stat = architecture;
      else if (!strcmp (reg, SYSCALL_NR))
        *reg_stat = syscall_nr;
      else
        *reg_stat = none;
      return reg;
    case BPF_IND:
      return NULL;
    case BPF_MEM:
      strncpy (reg, mem[k], REG_BUF_LEN);
      return REG2STR (offsetof (reg_mem, mem[k]));
    case BPF_LEN:
      snprintf (reg, REG_BUF_LEN, "0x%x", (uint32_t)sizeof (seccomp_data));
      return reg;
    case BPF_MSH:
      return NULL;
    default:
      PEXIT (INVALID_LD_LDX_MODE ": 0x%x", mode);
    }
}

static void
LD (filter *f_ptr)
{
  char *mode = load_reg (A, &A_status, f_ptr);
  if (mode == NULL)
    printf ("unknown ld mode: bpf_msh or bpf_ind, plz open an issue:)");
  else
    printf (BLUE_A " = " BLUE_S, mode);
}

static void
LDX (filter *f_ptr)
{
  char *mode = load_reg (X, &X_status, f_ptr);
  if (mode == NULL)
    printf ("unknown ldx mode: bpf_msh or bpf_ind, plz open an issue:)");
  else
    printf (BLUE_X " = " BLUE_S, mode);
}

static void
ST (filter *f_ptr)
{
  printf (BLUE_M " = " BLUE_A, f_ptr->k);
  strncpy (mem[f_ptr->k], A, REG_BUF_LEN);
}

static void
STX (filter *f_ptr)
{
  printf (BLUE_M " = " BLUE_X, f_ptr->k);
  strncpy (mem[f_ptr->k], X, REG_BUF_LEN);
}

static const char *alu_sym_tbl[]
    = { " += ", " -= ",  " *= ",  " /= ",  " &= ", " |= ",
        " ^= ", " %%= ", " <<= ", " >>= ", " = -" };

static const char *
ALU_OP (filter *f_ptr)
{
  uint16_t op = BPF_OP (f_ptr->code);

  switch (op)
    {
    case BPF_ADD:
      return alu_sym_tbl[0];
    case BPF_SUB:
      return alu_sym_tbl[1];
    case BPF_MUL:
      return alu_sym_tbl[2];
    case BPF_DIV:
      return alu_sym_tbl[3];
    case BPF_AND:
      return alu_sym_tbl[4];
    case BPF_OR:
      return alu_sym_tbl[5];
    case BPF_XOR:
      return alu_sym_tbl[6];
    case BPF_MOD:
      return alu_sym_tbl[7];
    case BPF_LSH:
      return alu_sym_tbl[8];
    case BPF_RSH:
      return alu_sym_tbl[9];
    case BPF_NEG:
      return alu_sym_tbl[10];
    default:
      PEXIT (INVALID_ALU_OP ": 0x%x", op);
    }
}

static void
ALU (filter *f_ptr)
{
  uint16_t src = BPF_SRC (f_ptr->code);
  char rval[REG_BUF_LEN - 0x10];
  const char *alu_sym;

  alu_sym = ALU_OP (f_ptr);

  printf (BLUE_A);
  printf ("%s", alu_sym);

  strcpy (A, "A");
  strcat (A, alu_sym);
  if (src == BPF_X)
    {
      strcpy (rval, "$X");
      A_status = none;
    }
  else if (src == BPF_K)
    snprintf (rval, REG_BUF_LEN - 0x10, "0x%x", f_ptr->k);
  else
    PEXIT (INVALID_ALU_SRC ": 0x%x", src);

  if (BPF_OP (f_ptr->code) == BPF_NEG)
    printf (BLUE_A);
  else
    printf (BLUE_S, rval);

  strcat (A, rval);
}

static uint8_t
JMP_MODE (filter *f_ptr)
{
  uint16_t jmode = BPF_OP (f_ptr->code);

  switch (jmode)
    {
    case BPF_JEQ:
      return 0;
    case BPF_JGT:
      return 1;
    case BPF_JGE:
      return 2;
    case BPF_JSET:
      return 3;
    default:
      PEXIT (INVALID_JMP_MODE ": 0x%x", jmode);
    }
}

static char *
try_transfer (uint32_t val)
{
  if (A_status == syscall_nr)
    return seccomp_syscall_resolve_num_arch (arch, val);
  if (A_status == architecture)
    return ARCH2STR (val);
  else
    return NULL;
}

static void
ret_same_type (uint32_t val, char val_str[REG_BUF_LEN])
{
  char *ret = try_transfer (val);
  if (ret != NULL)
    strncpy (val_str, ret, REG_BUF_LEN - 1);
  else
    snprintf (val_str, REG_BUF_LEN, "0x%x", val);
}

static void
JMP_SRC (filter *f_ptr, char cmpval_str[REG_BUF_LEN])
{
  uint16_t src = BPF_SRC (f_ptr->code);

  switch (src)
    {
    case BPF_X:
      strcpy (cmpval_str, "$X");
      return;
    case BPF_K:
      ret_same_type (f_ptr->k, cmpval_str);
      return;
    default:
      PEXIT (INVALID_JMP_SRC ": 0x%x", src);
    }
}

static uint32_t
JMP_GOTO (filter *f_ptr)
{
  uint16_t src = BPF_SRC (f_ptr->code);

  if (src == BPF_K)
    return f_ptr->k;
  else
    PEXIT (INVALID_JMP_SRC ": 0x%x", src);
}

const char *true_cmp_sym_tbl[4]
    = { "if (" BLUE_A " == " BLUE_S ") ", "if (" BLUE_A " > " BLUE_S ") ",
        "if (" BLUE_A " >= " BLUE_S ") ", "if (" BLUE_A " & " BLUE_S ") " };
const char *false_cmp_sym_tbl[4]
    = { "if (" BLUE_A " != " BLUE_S ") ", "if (" BLUE_A " < " BLUE_S ") ",
        "if (" BLUE_A " <= " BLUE_S ") ", "if !(" BLUE_A " & " BLUE_S ") " };

static void
JMP (filter *f_ptr, uint32_t pc)
{
  uint8_t cmp_sym_idx;
  char cmp_rval_str[REG_BUF_LEN];

  uint8_t jt = f_ptr->jt;
  uint8_t jf = f_ptr->jf;

  if (BPF_OP (f_ptr->code) == BPF_JA)
    {
      printf ("goto " FORMAT, pc + JMP_GOTO (f_ptr) + 2);
      return;
    }

  cmp_sym_idx = JMP_MODE (f_ptr);
  JMP_SRC (f_ptr, cmp_rval_str);

  if (jt == 0 && jf == 0)
    PEXIT ("%s", INVALID_JT_JF);

  if (jt == 0)
    {
      printf (false_cmp_sym_tbl[cmp_sym_idx], cmp_rval_str);
      printf ("goto " FORMAT, pc + jf + 2);
    }
  else if (jf == 0)
    {
      printf (true_cmp_sym_tbl[cmp_sym_idx], cmp_rval_str);
      printf ("goto " FORMAT, pc + jt + 2);
    }
  else
    {
      printf (true_cmp_sym_tbl[cmp_sym_idx], cmp_rval_str);
      printf ("goto " FORMAT, pc + jt + 2);
      printf (", else goto " FORMAT, pc + jf + 2);
    }
}

static uint32_t
RET_VAL (filter *f_ptr)
{
  uint16_t ret = BPF_RVAL (f_ptr->code);
  uint32_t retval;

  switch (ret)
    {
    case BPF_A:
      retval = strtoull_check (A, 0, INVALID_REG_A_VAL);
      return retval;
    case BPF_K:
      return f_ptr->k;
    default:
      PEXIT (INVALID_RET_MODE ": 0x%x", ret);
    }
}

static void
RET (filter *f_ptr)
{
  uint32_t retval = RET_VAL (f_ptr);
  char *retstr = RETVAL2STR (retval);

  if (retstr != NULL)
    printf ("return %s", retstr);
  else
    printf (INVALID_RET_VAL ": 0x%x", retval);
}

static void
MISC (filter *f_ptr)
{
  uint16_t mode = BPF_MISCOP (f_ptr->code);

  switch (mode)
    {
    case BPF_TAX:
      printf (BLUE_X " = " BLUE_A);
      strncpy (X, A, REG_BUF_LEN);
      X_status = A_status;
      return;
    case BPF_TXA:
      printf (BLUE_A " = " BLUE_X);
      strncpy (A, X, REG_BUF_LEN);
      A_status = X_status;
      return;
    default:
      printf (INVALID_MISC_MODE ": 0x%x", mode);
    }
}

static void
parse_class (filter *f_ptr, uint32_t pc)
{
  uint16_t cls = BPF_CLASS (f_ptr->code);

  switch (cls)
    {
    case BPF_LD:
      LD (f_ptr);
      return;
    case BPF_LDX:
      LDX (f_ptr);
      return;
    case BPF_ST:
      ST (f_ptr);
      return;
    case BPF_STX:
      STX (f_ptr);
      return;
    case BPF_ALU:
      ALU (f_ptr);
      return;
    case BPF_JMP:
      JMP (f_ptr, pc);
      return;
    case BPF_RET:
      RET (f_ptr);
      return;
    case BPF_MISC:
      MISC (f_ptr);
      return;
    default:
      printf (INVALID_CLASS ": 0x%x", cls);
    }
}

void
parse_filter (uint32_t arch_token, fprog *sock_prog, FILE *output_fileptr)
{
  arch = arch_token;
  prog = sock_prog;
  uint32_t len = prog->len;

  int stdout_backup = global_hide_stdout (fileno (output_fileptr));

  printf (" Line  CODE  JT   JF      K\n");
  printf ("---------------------------------\n");
  for (uint32_t i = 0; i < len; i++)
    {
      filter *f_ptr = &prog->filter[i];
      printf (" " FORMAT ": 0x%02x 0x%02x 0x%02x 0x%08x ", i + 1, f_ptr->code,
              f_ptr->jt, f_ptr->jf, f_ptr->k);
      parse_class (f_ptr, i);
      printf ("\n");
    }
  printf ("---------------------------------\n");

  global_ret_stdout (stdout_backup);
}
