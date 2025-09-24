#include "parsefilter.h"
#include "checkfilter.h"
#include "color.h"
#include "emu.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include "transfer.h"
#include <errno.h>
#include <fcntl.h>
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

static FILE *o_fp;

static fprog *prog;
static uint32_t arch;

static char A[REG_BUF_LEN] = "0";
static char X[REG_BUF_LEN] = "0";
static char mem[BPF_MEMWORDS][REG_BUF_LEN] = { "" };

typedef enum
{
  NONE = 0,
  ARCH = 1,
  SYS_NR = 2,
  UNKNOWN = 3,
} reg_stat;

typedef struct
{
  reg_stat A_stat;
  reg_stat X_stat;
  reg_stat mem_stat[BPF_MEMWORDS];
} stat_ctx;

static uint32_t pc = 0;

#define FORCE true

static void
set_stat (reg_stat *dest, reg_stat src, bool force)
{
  if (force)
  {
    *dest = src;
    return;
  }

  if (*dest == NONE)
    *dest = src;
  else if (*dest == src)
    *dest = src;
  else
    *dest = UNKNOWN;
}

static void
set_ctx (stat_ctx *dest, stat_ctx *src, bool force)
{
  set_stat (&dest->A_stat, src->A_stat, force);
  set_stat (&dest->X_stat, src->X_stat, force);
  for (uint32_t i = 0; i < BPF_MEMWORDS; i++)
    set_stat (&dest->mem_stat[i], src->mem_stat[i], force);
}

static char *
load_reg_abs (char reg[REG_BUF_LEN], reg_stat *status, filter *f_ptr)
{
  char *abs_name = 0;
  abs_name = ABS2STR (f_ptr->k);
  if (!abs_name)
    error ("%d %s", pc, INVALID_OFFSET_ABS);
  strcpy (reg, abs_name);
  if (!strcmp (reg, ARCHITECTURE))
    set_stat (status, ARCH, FORCE);
  else if (!strcmp (reg, SYSCALL_NR))
    set_stat (status, SYS_NR, FORCE);
  else
    set_stat (status, UNKNOWN, FORCE);
  return reg;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
static char *
load_reg (char reg[REG_BUF_LEN], reg_stat *reg_stat, filter *f_ptr,
          stat_ctx *ctx)
{
  uint16_t mode = BPF_MODE (f_ptr->code);
  uint32_t k = f_ptr->k;

  switch (mode)
    {
    case BPF_IMM:
      snprintf (reg, REG_BUF_LEN, "0x%x", k);
      set_stat (reg_stat, UNKNOWN, FORCE);
      return reg;
    case BPF_ABS:
      return load_reg_abs (reg, reg_stat, f_ptr);
    case BPF_MEM:
      if (*mem[k] == '\0')
        error ("%d %s", pc, ST_MEM_BEFORE_LD);
      set_stat (reg_stat, ctx->mem_stat[k], FORCE);
      strcpy (reg, mem[k]);
      return REG_MEM2STR (offsetof (reg_mem, mem[k]));
    }
}
#pragma GCC diagnostic pop

static void
LD (filter *f_ptr, stat_ctx *ctx)
{
  char *rval_str = load_reg (A, &ctx->A_stat, f_ptr, ctx);
  fprintf (o_fp, "%s = ", CYAN_A);
  fprintf (o_fp, CYAN_S, rval_str);
}

static void
LDX (filter *f_ptr, stat_ctx *ctx)
{
  char *rval_str = load_reg (X, &ctx->X_stat, f_ptr, ctx);
  fprintf (o_fp, "%s = ", CYAN_X);
  fprintf (o_fp, CYAN_S, rval_str);
}

static void
ST (filter *f_ptr, stat_ctx *ctx)
{
  fprintf (o_fp, CYAN_M, f_ptr->k);
  fprintf (o_fp, " = %s", CYAN_A);
  strncpy (mem[f_ptr->k], A, REG_BUF_LEN);
  set_stat (&ctx->mem_stat[f_ptr->k], ctx->A_stat, FORCE);
}

static void
STX (filter *f_ptr, stat_ctx *ctx)
{
  fprintf (o_fp, CYAN_M, f_ptr->k);
  fprintf (o_fp, " = %s", CYAN_X);
  strncpy (mem[f_ptr->k], X, REG_BUF_LEN);
  set_stat (&ctx->mem_stat[f_ptr->k], ctx->X_stat, FORCE);
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
ALU (filter *f_ptr, stat_ctx *ctx)
{
  uint16_t src = BPF_SRC (f_ptr->code);
  char rval[REG_BUF_LEN - 0x10];
  const char *alu_sym;

  alu_sym = ALU_OP (f_ptr);

  fprintf (o_fp, CYAN_A);
  fprintf (o_fp, "%s", alu_sym);

  strcpy (A, "A");
  strcat (A, alu_sym);

  if (BPF_OP (f_ptr->code) == BPF_NEG)
    strcpy (rval, "$A");
  else if (src == BPF_K)
    sprintf (rval, "0x%x", f_ptr->k);
  else if (src == BPF_X)
    strcpy (rval, "$X");
  fprintf (o_fp, CYAN_S, rval);
  strcat (A, rval);

  set_stat (&ctx->A_stat, UNKNOWN, FORCE);
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
try_transfer (uint32_t val, reg_stat A_stat)
{
  if (A_stat == SYS_NR)
    return seccomp_syscall_resolve_num_arch (arch, val);
  if (A_stat == ARCH)
    return ARCH2STR (val);
  else
    return NULL;
}

static void
ret_same_type (uint32_t val, char val_str[REG_BUF_LEN], reg_stat A_stat)
{
  char *ret = try_transfer (val, A_stat);
  if (ret != NULL)
    strncpy (val_str, ret, REG_BUF_LEN - 1);
  else
    snprintf (val_str, REG_BUF_LEN, "0x%x", val);
}

static void
JMP_SRC (filter *f_ptr, char cmpval_str[REG_BUF_LEN], reg_stat A_stat)
{
  uint16_t src = BPF_SRC (f_ptr->code);

  switch (src)
    {
    case BPF_X:
      strcpy (cmpval_str, "$X");
      return;
    case BPF_K:
      ret_same_type (f_ptr->k, cmpval_str, A_stat);
      return;
    }
}

const char *true_cmp_sym_tbl[4] = { " == ", " > ", " >= ", " & " };
const char *false_cmp_sym_tbl[4] = { " != ", " < ", " <= ", " & " };

static void
print_condition (const char *sym, char *rval_str)
{
  fprintf (o_fp, "%s", sym);
  fprintf (o_fp, CYAN_S, rval_str);
  fprintf (o_fp, ") ");
}

static void
JMP (filter *f_ptr, stat_ctx *stat_ctx_list)
{
  uint8_t cmp_sym_idx;
  char cmp_rval_str[REG_BUF_LEN];
  uint8_t jt = f_ptr->jt;
  uint8_t jf = f_ptr->jf;

  if (BPF_OP (f_ptr->code) == BPF_JA)
    {
      fprintf (o_fp, "goto " FORMAT, pc + f_ptr->k + 2);
      set_ctx (&stat_ctx_list[pc + f_ptr->k + 1], &stat_ctx_list[pc], !FORCE);
      return;
    }

  cmp_sym_idx = JMP_MODE (f_ptr);
  JMP_SRC (f_ptr, cmp_rval_str, stat_ctx_list[pc].A_stat);

  fprintf (o_fp, "if ");
  if (jt == 0 && cmp_sym_idx == 3)
    fprintf (o_fp, "!(");
  else
    fprintf (o_fp, "(");
  fprintf (o_fp, CYAN_A);

  if (jt == 0)
    {
      print_condition (false_cmp_sym_tbl[cmp_sym_idx], cmp_rval_str);
      set_ctx (&stat_ctx_list[pc + 1], &stat_ctx_list[pc], !FORCE);
      set_ctx (&stat_ctx_list[pc + jf + 1], &stat_ctx_list[pc], !FORCE);
      fprintf (o_fp, "goto " FORMAT, pc + jf + 2);
    }
  else if (jf == 0)
    {
      print_condition (true_cmp_sym_tbl[cmp_sym_idx], cmp_rval_str);
      set_ctx (&stat_ctx_list[pc + 1], &stat_ctx_list[pc], !FORCE);
      set_ctx (&stat_ctx_list[pc + jf + 1], &stat_ctx_list[pc], !FORCE);
      fprintf (o_fp, "goto " FORMAT, pc + jt + 2);
    }
  else
    {
      print_condition (true_cmp_sym_tbl[cmp_sym_idx], cmp_rval_str);
      set_ctx (&stat_ctx_list[pc + jt + 1], &stat_ctx_list[pc], !FORCE);
      set_ctx (&stat_ctx_list[pc + jf + 1], &stat_ctx_list[pc], !FORCE);
      fprintf (o_fp, "goto " FORMAT, pc + jt + 2);
      fprintf (o_fp, ", else goto " FORMAT, pc + jf + 2);
    }

  if (jt == 0 && jf == 0)
    {
      fprintf (o_fp, "\n\n");
      warn ("%s", JT_JF_BOTH_ZERO);
    }
  // turns out this is allowed by kernel
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
      error ("%d %s", pc, INVALID_RET_VAL);
    }

  fprintf (o_fp, "return %s", ret_str);
}

static void
MISC (filter *f_ptr, stat_ctx *ctx)
{
  uint16_t mode = BPF_MISCOP (f_ptr->code);

  switch (mode)
    {
    case BPF_TAX:
      fprintf (o_fp, "%s = %s", CYAN_X, CYAN_A);
      strncpy (X, A, REG_BUF_LEN);
      set_stat (&ctx->A_stat, ctx->X_stat, FORCE);
      return;
    case BPF_TXA:
      fprintf (o_fp, "%s = %s", CYAN_A, CYAN_X);
      strncpy (A, X, REG_BUF_LEN);
      set_stat (&ctx->X_stat, ctx->A_stat, FORCE);
      return;
    }
}

static void
parse_class (filter *f_ptr, stat_ctx *stat_list)
{
  uint16_t cls = BPF_CLASS (f_ptr->code);
  stat_ctx *ctx = &stat_list[pc];

  switch (cls)
    {
    case BPF_LD:
      LD (f_ptr, ctx);
      break;
    case BPF_LDX:
      LDX (f_ptr, ctx);
      break;
    case BPF_ST:
      ST (f_ptr, ctx);
      break;
    case BPF_STX:
      STX (f_ptr, ctx);
      break;
    case BPF_ALU:
      ALU (f_ptr, ctx);
      break;
    case BPF_JMP:
      JMP (f_ptr, stat_list);
      break;
    case BPF_RET:
      RET (f_ptr);
      return;
    case BPF_MISC:
      MISC (f_ptr, ctx);
      break;
    }
  if (cls != BPF_JMP)
    set_ctx (&stat_list[pc + 1], &stat_list[pc], !FORCE);
}

void
parse_filter (uint32_t arch_token, fprog *sock_prog, FILE *output_fp)
{
  arch = arch_token;
  prog = sock_prog;
  uint32_t len = prog->len;
  o_fp = output_fp;

  bool error_happen = scmp_check_filter (prog->filter, len);

  stat_ctx *stat_list;
  stat_list = malloc (sizeof (stat_ctx) * len);
  if (stat_list == NULL)
    error ("%s", strerror (errno));
  memset (stat_list, NONE, sizeof (stat_ctx) * len);
  // unknown is zero, so doing this is ok

  fprintf (o_fp, " Line  CODE  JT   JF      K\n");
  fprintf (o_fp, "---------------------------------\n");
  for (; pc < len; pc++)
    {
      filter *f_ptr = &prog->filter[pc];

      fprintf (o_fp, " " FORMAT, pc + 1);
      fprintf (o_fp, ": 0x%02x 0x%02x ", f_ptr->code, f_ptr->jt);
      fprintf (o_fp, "0x%02x 0x%08x ", f_ptr->jf, f_ptr->k);

      parse_class (f_ptr, stat_list);

      fprintf (o_fp, "\n");
    }
  fprintf (o_fp, "---------------------------------\n");
  pc = 0;

  free (stat_list);

  if (error_happen == true)
    warn ("%s", ERROR_HAPPEN);
}
