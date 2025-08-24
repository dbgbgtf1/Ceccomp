#include "parsefilter.h"
#include "checkfilter.h"
#include "color.h"
#include "emu.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include "transfer.h"
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REG_BUF_LEN 0x100

static FILE *s_output_fp;

static fprog *prog;
static uint32_t arch;

static char A[REG_BUF_LEN] = "0";
static char X[REG_BUF_LEN] = "0";
static char mem[BPF_MEMWORDS][REG_BUF_LEN] = { "" };

typedef enum
{
  architecture = 0,
  syscall_nr = 1,
  none = 2,
} reg_status;

static reg_status A_status = none;
static reg_status X_status = none;

static uint32_t parse_idx = 0;

static char *
load_reg_abs (char reg[REG_BUF_LEN], reg_status *reg_stat, filter *f_ptr)
{
  char *abs_name = 0;
  abs_name = ABS2STR (f_ptr->k);
  if (!abs_name)
    error ("%d %s", parse_idx, INVALID_OFFSET_ABS);
  strcpy (reg, abs_name);
  if (!strcmp (reg, ARCHITECTURE))
    *reg_stat = architecture;
  else if (!strcmp (reg, SYSCALL_NR))
    *reg_stat = syscall_nr;
  else
    *reg_stat = none;
  return reg;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
static char *
load_reg (char reg[REG_BUF_LEN], reg_status *reg_stat, filter *f_ptr)
{
  uint16_t mode = BPF_MODE (f_ptr->code);
  uint32_t k = f_ptr->k;

  switch (mode)
    {
    case BPF_IMM:
      snprintf (reg, REG_BUF_LEN, "0x%x", k);
      return reg;
    case BPF_ABS:
      return load_reg_abs (reg, reg_stat, f_ptr);
    case BPF_MEM:
      if (*mem[k] == '\0')
        error ("%d %s", parse_idx, ST_MEM_BEFORE_LD);
      strcpy (reg, mem[k]);
      return REG_MEM2STR (offsetof (reg_mem, mem[k]));
    }
}
#pragma GCC diagnostic pop

static void
LD (filter *f_ptr)
{
  char *rval_str = load_reg (A, &A_status, f_ptr);
  fprintf (s_output_fp, "%s = ", CYAN_A);
  fprintf (s_output_fp, CYAN_S, rval_str);
}

static void
LDX (filter *f_ptr)
{
  char *rval_str = load_reg (X, &X_status, f_ptr);
  fprintf (s_output_fp, "%s = ", CYAN_X);
  fprintf (s_output_fp, CYAN_S, rval_str);
}

static void
ST (filter *f_ptr)
{
  fprintf (s_output_fp, CYAN_M, f_ptr->k);
  fprintf (s_output_fp, " = %s", CYAN_A);
  strncpy (mem[f_ptr->k], A, REG_BUF_LEN);
}

static void
STX (filter *f_ptr)
{
  fprintf (s_output_fp, CYAN_M, f_ptr->k);
  fprintf (s_output_fp, " = %s", CYAN_X);
  strncpy (mem[f_ptr->k], X, REG_BUF_LEN);
}

static const char *alu_sym_tbl[]
    = { " += ", " -= ", " *= ",  " /= ",  " &= ",
        " |= ", " ^= ", " <<= ", " >>= ", " = -" };

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
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
    case BPF_LSH:
      return alu_sym_tbl[7];
    case BPF_RSH:
      return alu_sym_tbl[8];
    case BPF_NEG:
      return alu_sym_tbl[9];
    }
}
#pragma GCC diagnostic pop

static void
ALU (filter *f_ptr)
{
  uint16_t src = BPF_SRC (f_ptr->code);
  char rval[REG_BUF_LEN - 0x10];
  const char *alu_sym;

  alu_sym = ALU_OP (f_ptr);

  fprintf (s_output_fp, CYAN_A);
  fprintf (s_output_fp, "%s", alu_sym);

  strcpy (A, "A");
  strcat (A, alu_sym);

  if (BPF_OP (f_ptr->code) == BPF_NEG)
    strcpy (rval, "$A");
  else if (src == BPF_K)
    sprintf (rval, "0x%x", f_ptr->k);
  else if (src == BPF_X)
    {
      strcpy (rval, "$X");
      A_status = none;
    }
  fprintf (s_output_fp, CYAN_S, rval);
  strcat (A, rval);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
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
    }
}
#pragma GCC diagnostic pop

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
    }
}

const char *true_cmp_sym_tbl[4] = { " == ", " > ", " >= ", " & " };
const char *false_cmp_sym_tbl[4] = { " != ", " < ", " <= ", " & " };

static void
print_condition (const char *sym, char *rval_str)
{
  fprintf (s_output_fp, "%s", sym);
  fprintf (s_output_fp, CYAN_S, rval_str);
  fprintf (s_output_fp, ") ");
}

static void
JMP (filter *f_ptr, uint32_t pc)
{
  uint8_t cmp_sym_idx;
  char cmp_rval_str[REG_BUF_LEN];

  uint8_t jt = f_ptr->jt;
  uint8_t jf = f_ptr->jf;

  if (BPF_OP (f_ptr->code) == BPF_JA)
    {
      fprintf (s_output_fp, "goto " FORMAT, pc + f_ptr->k + 2);
      return;
    }

  cmp_sym_idx = JMP_MODE (f_ptr);
  JMP_SRC (f_ptr, cmp_rval_str);

  // if (jt == 0 && jf == 0)
  // log_warn(JT_JF_BOTH_ZERO);
  // turns out this is allowed by kernel

  fprintf (s_output_fp, "if ");
  if (jt == 0 && cmp_sym_idx == 3)
    fprintf (s_output_fp, "!(");
  else
    fprintf (s_output_fp, "(");
  fprintf (s_output_fp, CYAN_A);

  if (jt == 0)
    {
      print_condition (false_cmp_sym_tbl[cmp_sym_idx], cmp_rval_str);
      fprintf (s_output_fp, "goto " FORMAT, pc + jf + 2);
    }
  else if (jf == 0)
    {
      print_condition (true_cmp_sym_tbl[cmp_sym_idx], cmp_rval_str);
      fprintf (s_output_fp, "goto " FORMAT, pc + jt + 2);
    }
  else
    {
      print_condition (true_cmp_sym_tbl[cmp_sym_idx], cmp_rval_str);
      fprintf (s_output_fp, "goto " FORMAT, pc + jt + 2);
      fprintf (s_output_fp, ", else goto " FORMAT, pc + jf + 2);
    }
}

static void
RET (filter *f_ptr)
{
  char *ret_str;
  uint16_t ret = BPF_RVAL (f_ptr->code);

  switch (ret)
    {
    case BPF_A:
      ret_str = CYAN ("$A");
      break;
    case BPF_K:
      ret_str = RETVAL2STR (f_ptr->k);
      break;
    default:
      error ("%d %s", parse_idx, INVALID_RET_VAL);
    }

  fprintf (s_output_fp, "return %s", ret_str);
}

static void
MISC (filter *f_ptr)
{
  uint16_t mode = BPF_MISCOP (f_ptr->code);

  switch (mode)
    {
    case BPF_TAX:
      fprintf (s_output_fp, "%s = %s", CYAN_X, CYAN_A);
      strncpy (X, A, REG_BUF_LEN);
      X_status = A_status;
      return;
    case BPF_TXA:
      fprintf (s_output_fp, "%s = %s", CYAN_A, CYAN_X);
      strncpy (A, X, REG_BUF_LEN);
      A_status = X_status;
      return;
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
    }
}

void
parse_filter (uint32_t arch_token, fprog *sock_prog, FILE *output_fp)
{
  arch = arch_token;
  prog = sock_prog;
  uint32_t len = prog->len;
  s_output_fp = output_fp;

  bool error_happen = scmp_check_filter (prog->filter, len);

  fprintf (s_output_fp, " Line  CODE  JT   JF      K\n");
  fprintf (s_output_fp, "---------------------------------\n");
  for (; parse_idx < len; parse_idx++)
    {
      filter *f_ptr = &prog->filter[parse_idx];

      fprintf (s_output_fp, " " FORMAT, parse_idx + 1);
      fprintf (s_output_fp, ": 0x%02x 0x%02x ", f_ptr->code, f_ptr->jt);
      fprintf (s_output_fp, "0x%02x 0x%08x ", f_ptr->jf, f_ptr->k);

      parse_class (f_ptr, parse_idx);

      fprintf (s_output_fp, "\n");
    }
  fprintf (s_output_fp, "---------------------------------\n");

  if (error_happen == true)
    warn ("%s", ERROR_HAPPEN);
}
