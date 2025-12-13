#include "parsefilter.h"
#include "checkfilter.h"
#include "color.h"
#include "emu.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include "transfer.h"
#include <argp.h>
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

static uint32_t pc = 0;
static uint32_t default_arch;

static char A[REG_BUF_LEN] = "0";
static char X[REG_BUF_LEN] = "0";
static char mem[BPF_MEMWORDS][REG_BUF_LEN] = { "" };

// don't change these enum vals, I set them on purpose
typedef enum
{
  UNKNOWN = -1,
  NONE = 0,
  ARCH = 1,
  SYS_NR = 2,
} reg_stat;

typedef struct
{
  reg_stat A_stat;
  reg_stat X_stat;
  reg_stat mem_stat[BPF_MEMWORDS];
  uint32_t arch;
} stat_ctx;

#define FORCE true

typedef enum
{
  EQUAL = 0,
  JG_JL = 1,
  JGE_JLE = 2,
  JSET = 3,
} cmp_sym;

const char *true_cmp_sym_tbl[4] = { " == ", " > ", " >= ", " & " };
const char *false_cmp_sym_tbl[4] = { " != ", " <= ", " < ", " & " };

static void
set_stat (reg_stat *dest, reg_stat src, bool force)
{
  if (force || *dest == NONE)
    *dest = src;
  // after this, *dest == src, so the next judgement will be ignored

  if (*dest != src)
    *dest = UNKNOWN;
  // if *dest == src, nothing need to be done
}

// see set_stat for details
static void
set_arch (uint32_t *dest, uint32_t src, bool force)
{
  if (force || *dest == NONE)
    *dest = src;

  if (*dest != src)
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
load_reg_abs (reg_stat *status, filter *f_ptr)
{
  char *abs_name = NULL;
  abs_name = ABS2STR (f_ptr->k);
  if (!abs_name)
    error ("%d %s", pc, INVALID_OFFSET_ABS);

  if (!strcmp (abs_name, ARCHITECTURE))
    set_stat (status, ARCH, FORCE);
  else if (!strcmp (abs_name, SYSCALL_NR))
    set_stat (status, SYS_NR, FORCE);
  else
    set_stat (status, UNKNOWN, FORCE);
  return abs_name;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
static void
load_reg (char reg[REG_BUF_LEN], reg_stat *reg_stat, filter *f_ptr,
          stat_ctx *ctx)
{
  uint16_t mode = BPF_MODE (f_ptr->code);
  uint32_t k = f_ptr->k;

  switch (mode)
    {
    case BPF_IMM:
      snprintf (reg, REG_BUF_LEN, "0x%x", k);
      fprintf (o_fp, BRIGHT_CYAN ("0x%x"), k);
      set_stat (reg_stat, UNKNOWN, FORCE);
      return;
    case BPF_ABS:
      snprintf (reg, REG_BUF_LEN, "%s", load_reg_abs (reg_stat, f_ptr));
      fprintf (o_fp, BRIGHT_BLUE ("%s"), reg);
      return;
    case BPF_MEM:
      if (*mem[k] == '\0')
        error ("%d %s", pc, ST_MEM_BEFORE_LD);
      snprintf (reg, REG_BUF_LEN, "%s", mem[k]);
      fprintf (o_fp, BRIGHT_YELLOW ("%s"),
               REG_MEM2STR (offsetof (reg_mem, mem[k])));
      set_stat (reg_stat, ctx->mem_stat[k], FORCE);
      return;
    }
}
#pragma GCC diagnostic pop

static void
LD (filter *f_ptr, stat_ctx *ctx)
{
  fprintf (o_fp, "%s = ", BRIGHT_YELLOW ("$A"));
  load_reg (A, &ctx->A_stat, f_ptr, ctx);
}

static void
LDX (filter *f_ptr, stat_ctx *ctx)
{
  fprintf (o_fp, "%s = ", BRIGHT_YELLOW ("$X"));
  load_reg (X, &ctx->X_stat, f_ptr, ctx);
}

static void
ST (filter *f_ptr, stat_ctx *ctx)
{
  fprintf (o_fp, BRIGHT_YELLOW ("$mem[0x%1x]"), f_ptr->k);
  fprintf (o_fp, " = %s", BRIGHT_YELLOW ("$A"));
  strncpy (mem[f_ptr->k], A, REG_BUF_LEN);
  set_stat (&ctx->mem_stat[f_ptr->k], ctx->A_stat, FORCE);
}

static void
STX (filter *f_ptr, stat_ctx *ctx)
{
  fprintf (o_fp, BRIGHT_YELLOW ("$mem[0x%1x]"), f_ptr->k);
  fprintf (o_fp, " = %s", BRIGHT_YELLOW ("$X"));
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

  fprintf (o_fp, BRIGHT_YELLOW ("$A"));
  fprintf (o_fp, "%s", alu_sym);

  strcpy (A, "A");
  strcat (A, alu_sym);

  if (BPF_OP (f_ptr->code) == BPF_NEG)
    strcpy (rval, BRIGHT_YELLOW ("$A"));
  else if (src == BPF_K)
    sprintf (rval, BRIGHT_CYAN ("0x%x"), f_ptr->k);
  else if (src == BPF_X)
    strcpy (rval, BRIGHT_YELLOW ("$X"));

  fprintf (o_fp, "%s", rval);
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
      return EQUAL;
    case BPF_JGT:
      return JG_JL;
    case BPF_JGE:
      return JGE_JLE;
    case BPF_JSET:
      return JSET;
    }
}
#pragma GCC diagnostic pop

static void
ret_same_type (uint32_t val, char val_str[REG_BUF_LEN], reg_stat A_stat,
               uint32_t arch)
{
  char *rval_str = NULL;
  if (A_stat == SYS_NR)
    {
      rval_str = seccomp_syscall_resolve_num_arch (arch, val);
      if (!rval_str)
        snprintf (val_str, REG_BUF_LEN, BRIGHT_CYAN ("0x%x"), val);
      else if (arch == default_arch)
        snprintf (val_str, REG_BUF_LEN, BRIGHT_CYAN ("%s"), rval_str);
      else
        snprintf (val_str, REG_BUF_LEN, BRIGHT_CYAN ("%s.%s"), ARCH2STR (arch),
                  rval_str);
      free (rval_str);
      return;
    }
  else if (A_stat == ARCH)
    {
      rval_str = ARCH2STR (val);
      snprintf (val_str, REG_BUF_LEN, BRIGHT_CYAN ("%s"), rval_str);
      return;
    }
  else
    snprintf (val_str, REG_BUF_LEN, BRIGHT_CYAN ("0x%x"), val);
}

static void
JMP_SRC (filter *f_ptr, char cmpval_str[REG_BUF_LEN], reg_stat A_stat,
         uint32_t arch)
{
  uint16_t src = BPF_SRC (f_ptr->code);

  switch (src)
    {
    case BPF_X:
      strcpy (cmpval_str, BRIGHT_YELLOW ("$X"));
      return;
    case BPF_K:
      ret_same_type (f_ptr->k, cmpval_str, A_stat, arch);
      return;
    }
}

static void
print_condition (const char *sym, char *rval_str)
{
  fprintf (o_fp, "%s", sym);
  fprintf (o_fp, "%s", rval_str);
  fprintf (o_fp, ") ");
}

static void
JMP_JA (stat_ctx *stat_list, uint32_t pc, uint32_t k)
{
  set_ctx (&stat_list[pc + k + 1], &stat_list[pc], !FORCE);
  set_arch (&stat_list[pc + k + 1].arch, stat_list[pc].arch, !FORCE);
  fprintf (o_fp, "goto " FORMAT, pc + k + 2);
  return;
}

static void
JMP (filter *f_ptr, stat_ctx *stat_list)
{
  uint8_t cmp_sym_idx;
  char cmp_rval_str[REG_BUF_LEN];

  if (BPF_OP (f_ptr->code) == BPF_JA)
    {
      JMP_JA (stat_list, pc, f_ptr->k);
      return;
    }

  uint8_t jt = f_ptr->jt;
  uint8_t jf = f_ptr->jf;

  set_ctx (&stat_list[pc + jt + 1], &stat_list[pc], !FORCE);
  set_ctx (&stat_list[pc + jf + 1], &stat_list[pc], !FORCE);
  // jmp always jmp to `pc + jt + 1` or `pc + jf + 1`

  cmp_sym_idx = JMP_MODE (f_ptr);
  JMP_SRC (f_ptr, cmp_rval_str, stat_list[pc].A_stat, stat_list[pc].arch);
  // if A_stat == ARCH, then try to predict
  if (stat_list[pc].A_stat == ARCH)
    {
      if (cmp_sym_idx == EQUAL)
        {
          // if we take this branch, f_ptr->k here must be cmp_rval arch
          set_arch (&stat_list[pc + jt + 1].arch, f_ptr->k, !FORCE);
          set_arch (&stat_list[pc + jf + 1].arch, UNKNOWN, !FORCE);
        }
    }
  else
    {
      set_arch (&stat_list[pc + jt + 1].arch, stat_list[pc].arch, !FORCE);
      set_arch (&stat_list[pc + jf + 1].arch, stat_list[pc].arch, !FORCE);
    }

  fprintf (o_fp, "if ");
  if (jt == 0 && cmp_sym_idx == 3)
    fprintf (o_fp, "!(");
  else
    fprintf (o_fp, "(");
  fprintf (o_fp, BRIGHT_YELLOW ("$A"));

  if (jt == 0)
    {
      print_condition (false_cmp_sym_tbl[cmp_sym_idx], cmp_rval_str);
      fprintf (o_fp, "goto " FORMAT, pc + jf + 2);
    }
  else if (jf == 0)
    {
      print_condition (true_cmp_sym_tbl[cmp_sym_idx], cmp_rval_str);
      fprintf (o_fp, "goto " FORMAT, pc + jt + 2);
    }
  else
    {
      print_condition (true_cmp_sym_tbl[cmp_sym_idx], cmp_rval_str);
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
      ret_str = BRIGHT_YELLOW ("$A");
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
      fprintf (o_fp, "%s = %s", BRIGHT_YELLOW ("$X"), BRIGHT_YELLOW ("$A"));
      strncpy (X, A, REG_BUF_LEN);
      set_stat (&ctx->A_stat, ctx->X_stat, FORCE);
      return;
    case BPF_TXA:
      fprintf (o_fp, "%s = %s", BRIGHT_YELLOW ("$A"), BRIGHT_YELLOW ("$X"));
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
      return;
    case BPF_RET:
      RET (f_ptr);
      return;
    case BPF_MISC:
      MISC (f_ptr, ctx);
      break;
    }

  set_ctx (&stat_list[pc + 1], &stat_list[pc], !FORCE);
  set_arch (&stat_list[pc + 1].arch, stat_list[pc].arch, !FORCE);
}

void
parse_filter (uint32_t arch_token, fprog *sock_prog, FILE *output_fp)
{
  prog = sock_prog;
  uint32_t len = prog->len;
  uint32_t jmp_len = len;
  o_fp = output_fp;

  bool error_happen = scmp_check_filter (prog->filter, len, &jmp_len);

  stat_ctx *stat_list;
  stat_list = malloc (sizeof (stat_ctx) * jmp_len);
  if (stat_list == NULL)
    error ("malloc: %s", strerror (errno));
  memset (stat_list, NONE, sizeof (stat_ctx) * jmp_len);
  // none is zero, so doing this is fine
  stat_list[0].arch = arch_token;
  default_arch = arch_token;

  fprintf (o_fp, " Label  CODE  JT   JF      K\n");
  fprintf (o_fp, "----------------------------------\n");
  for (; pc < len; pc++)
    {
      filter *f_ptr = &prog->filter[pc];

      fprintf (o_fp, " " FORMAT, pc + 1);
      fprintf (o_fp, ": 0x%02x 0x%02x ", f_ptr->code, f_ptr->jt);
      fprintf (o_fp, "0x%02x 0x%08x ", f_ptr->jf, f_ptr->k);

      parse_class (f_ptr, stat_list);

      fprintf (o_fp, "\n");
    }
  fprintf (o_fp, "----------------------------------\n");
  fflush (o_fp);
  pc = 0;

  free (stat_list);

  if (error_happen == true)
    warn ("%s", ERROR_HAPPEN);
}
