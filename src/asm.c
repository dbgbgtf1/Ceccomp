#include "asm.h"
#include "color.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include "parseargs.h"
#include "parseobj.h"
#include "preasm.h"
#include "transfer.h"
#include <fcntl.h>
#include <libintl.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>

static uint32_t idx;
char *origin_line;
char *clean_line;

static filter
MISC_TXA (void)
{
  return (filter)BPF_STMT (BPF_MISC | BPF_TXA, 0);
}

static filter
MISC_TAX (void)
{
  return (filter)BPF_STMT (BPF_MISC | BPF_TAX, 0);
}

// #pragma GCC diagnostic push
// #pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
// comparing the sym
// also EQ and NE can be the same thing
// only you have to reverse
static uint16_t
jmp_mode (uint8_t cmp_enum, bool *reverse)
{
  switch (cmp_enum)
    {
    case CMP_NE:
      *reverse = !*reverse;
    // fall through
    case CMP_EQ:
      return BPF_JEQ;

    case CMP_LE:
      *reverse = !*reverse;
    // fall through
    case CMP_GT:
      return BPF_JGT;

    case CMP_LT:
      *reverse = !*reverse;
    // fall through
    case CMP_GE:
      return BPF_JGE;

    case CMP_AD:
      return BPF_JSET;
    default:
      error ("%s", INPOSSIBLE_CMP_ENUM);
    }
}

static filter
JMP_GOTO (uint32_t pc)
{
  char *jmp_nr = clean_line + strlen ("gotoL");

  filter filter = BPF_JUMP (BPF_JMP | BPF_JA, 0, 0, 0);
  char *end;
  filter.k = strtol (jmp_nr, &end, 10) - pc - 1;

  if (jmp_nr == end)
    error (FORMAT " %s: %s", idx, INVALID_NR_AFTER_GOTO, origin_line);

  return filter;
}

static filter
JMP (uint32_t pc, uint32_t arch)
{
  filter filter = BPF_JUMP (BPF_JMP, 0, 0, 0);

  bool reverse = maybe_reverse (clean_line);
  char *cmp_str;
  if (reverse)
    cmp_str = clean_line + strlen ("if!($A");
  else
    cmp_str = clean_line + strlen ("if($A");

  uint8_t sym_enum = parse_cmp_sym (cmp_str);
  uint8_t sym_len = GETSYMLEN (sym_enum);

  filter.code |= jmp_mode (sym_enum, &reverse);

  char *rval = cmp_str + sym_len;
  if (STARTWITH (rval, "$X"))
    filter.code |= BPF_X;
  else
    {
      filter.code |= BPF_K;
      filter.k |= right_val_ifline (rval, NULL, arch);
    }

  char *right_paren = strchr (rval, ')');
  if (right_paren == NULL)
    error (FORMAT " %s: %s", idx, PAREN_WRAP_CONDITION, origin_line);

  uint32_t jmp_set = parse_goto (right_paren + 1);
  uint16_t jt = GETJT (jmp_set);
  uint16_t jf = GETJF (jmp_set);

  // if jt != 0 and jt <= pc, something mush be wrong
  if ((jt && (jt <= pc)) || (jf && (jf <= pc)))
    error (FORMAT " %s: %s", idx, JMP_NR_LESS_THAN_PC, origin_line);

  if (reverse)
    {
      filter.jt = jf ? (jf - pc - 1) : 0;
      filter.jf = jt ? (jt - pc - 1) : 0;
    }
  else
    {
      filter.jt = jt ? (jt - pc - 1) : 0;
      filter.jf = jf ? (jf - pc - 1) : 0;
    }

  return filter;
}

static bool
LD_LDX_LEN (char *rval_str, filter *f_ptr)
{
  if (strcmp (rval_str, SCMP_DATA_LEN))
    return false;

  f_ptr->code |= (BPF_W | BPF_LEN);
  f_ptr->k = sizeof (seccomp_data);
  return true;
}

static bool
LD_LDX_ABS (char *rval_str, filter *f_ptr)
{
  uint32_t offset = STR2ABS (rval_str);
  if (offset == (uint32_t)-1)
    return false;

  f_ptr->code |= (BPF_W | BPF_ABS);
  f_ptr->k = offset;
  return true;
}

static bool
LD_LDX_MEM (char *rval_str, filter *f_ptr)
{
  char *end;
  if (!STARTWITH (rval_str, "$mem["))
    return false;

  rval_str += strlen ("$mem[");
  uint32_t mem_idx = strtol (rval_str, &end, 0);

  if (*end != ']')
    error (FORMAT " %s: %s", idx, INVALID_MEM, origin_line);
  if (mem_idx >= BPF_MEMWORDS)
    error (FORMAT " %s: %s", idx, INVALID_MEM_IDX, origin_line);

  f_ptr->code |= BPF_MEM;
  f_ptr->k = mem_idx;
  return true;
}

static bool
LD_LDX_IMM (char *rval_str, filter *f_ptr, uint32_t arch)
{
  char *end;
  f_ptr->code |= BPF_IMM;
  f_ptr->k = seccomp_syscall_resolve_name_arch (arch, rval_str);
  if (f_ptr->k != (uint32_t)__NR_SCMP_ERROR)
    return true;

  f_ptr->k = strtoul (rval_str, &end, 0);
  if (end == rval_str)
    return false;
  return true;
}

static filter
LD_LDX (uint32_t arch)
{
  filter filter = { 0, 0, 0, 0 };
  char *rval_str = clean_line + 3;
  if (*(clean_line + 1) == 'A')
    {
      filter.code |= BPF_LD;
      if (LD_LDX_ABS (rval_str, &filter))
        return filter;
    }
  else if (*(clean_line + 1) == 'X')
    filter.code |= BPF_LDX;
  else
    error (FORMAT " %s: %s", idx, INVALID_LEFT_VAR, origin_line);

  if (LD_LDX_MEM (rval_str, &filter))
    return filter;
  else if (LD_LDX_IMM (rval_str, &filter, arch))
    return filter;
  else if (LD_LDX_LEN (rval_str, &filter))
    return filter;

  error (FORMAT " %s: %s", idx, INVALID_RIGHT_VAL, origin_line);
}

static filter
RET (void)
{
  filter filter = { BPF_RET, 0, 0, 0 };

  char *retval_str = clean_line + strlen ("return");

  int32_t retval = STR2RETVAL (retval_str);
  if (retval != -1)
    {
      filter.code |= BPF_K;
      filter.k |= retval;
    }
  else if (STARTWITH (retval_str, "$A"))
    filter.code |= BPF_A;
  else
    error (FORMAT " %s: %s", idx, INVALID_RET, origin_line);

  return filter;
}

static filter
ST_STX (void)
{
  filter filter = { 0 };

  char *idx_str = clean_line + strlen ("$mem[");
  char *end;
  uint32_t mem_idx = strtol (idx_str, &end, 0);
  if (*end != ']')
    error (FORMAT " %s: %s", idx, INVALID_MEM, origin_line);
  if (*(end + 1) != '=')
    error (FORMAT " %s: %s", idx, INVALID_OPERATOR, origin_line);
  if (mem_idx >= BPF_MEMWORDS)
    error (FORMAT " %s: %s", idx, INVALID_MEM_IDX, origin_line);

  filter.k = mem_idx;

  if (*(end + 2) != '$')
    error (FORMAT " %s: %s", idx, INVALID_RIGHT_VAL, origin_line);

  if (*(end + 3) == 'A')
    filter.code |= BPF_ST;
  else if (*(end + 3) == 'X')
    filter.code |= BPF_STX;
  else
    error (FORMAT " %s: %s", idx, INVALID_RIGHT_VAL, origin_line);

  return filter;
}

static uint16_t
alu_mode (uint8_t alu_enum)
{
  switch (alu_enum)
    {
    case ALU_AD:
      return BPF_ADD;
    case ALU_SU:
      return BPF_SUB;
    case ALU_ML:
      return BPF_MUL;
    case ALU_DV:
      return BPF_DIV;
    case ALU_OR:
      return BPF_OR;
    case ALU_AN:
      return BPF_AND;
    case ALU_LS:
      return BPF_LSH;
    case ALU_RS:
      return BPF_RSH;
    case ALU_XO:
      return BPF_XOR;
    default:
      error ("%s", INPOSSIBLE_ALU_ENUM);
    }
}

static filter
ALU (void)
{
  filter filter = BPF_STMT (BPF_ALU, 0);

  if (STARTWITH (clean_line, "$A=-$A"))
    {
      filter.code |= BPF_NEG;
      return filter;
    }

  char *sym_str = clean_line + strlen ("$A");
  uint8_t sym_enum = parse_alu_sym (sym_str);
  uint8_t sym_len = GETSYMLEN (sym_enum);

  filter.code |= alu_mode (sym_enum);

  char *rval_str = sym_str + sym_len;
  if (!strcmp (rval_str, "$X"))
    {
      filter.code |= BPF_X;
      return filter;
    }
  filter.code |= BPF_K;

  char *end;
  filter.k = strtoul (rval_str, &end, 0);
  if (rval_str == end)
    error (FORMAT " %s: %s", idx, INVALID_RIGHT_VAL, origin_line);
  return filter;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-type"
static char *
set_print_format (print_mode p_mode)
{
  if (p_mode == HEXFMT)
    return "\"\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\",\n";
  else if (p_mode == HEXLINE)
    return "\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x";
  else if (p_mode == RAW)
    return "%c%c%c%c%c%c%c%c";
}
#pragma GCC diagnostic pop

static void
format_print (filter filter, char *format)
{
  uint8_t *ptr = (uint8_t *)&filter;

  printf (format, ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6],
          ptr[7]);
}

void
assemble (uint32_t arch, FILE *read_fp, print_mode p_mode)
{
  idx = 1;

  char *format = set_print_format (p_mode);

  while (pre_asm (read_fp, &origin_line, &clean_line), origin_line != NULL)
    {
      filter f_current = { 0 };
      set_error_log (origin_line, idx);

      if (!strcmp (clean_line, "$A=$X"))
        f_current = MISC_TXA ();
      else if (!strcmp (clean_line, "$X=$A"))
        f_current = MISC_TAX ();
      else if (STARTWITH (clean_line, "if"))
        f_current = JMP (idx, arch);
      else if (STARTWITH (clean_line, "goto"))
        f_current = JMP_GOTO (idx);
      else if (STARTWITH (clean_line, "return"))
        f_current = RET ();
      else if (STARTWITH (clean_line, "$A=-$A"))
        f_current = ALU ();
      else if (STARTWITH (clean_line, "$mem["))
        f_current = ST_STX ();
      else if (STARTWITH (clean_line, "$") && *(clean_line + 2) == '=')
        f_current = LD_LDX (arch);
      else if (STARTWITH (clean_line, "$A"))
        f_current = ALU ();
      else
        error (FORMAT " %s: %s", idx, INVALID_ASM_CODE, origin_line);

      format_print (f_current, format);
      idx++;
    }

  if (p_mode != RAW)
    putchar ('\n');
}
