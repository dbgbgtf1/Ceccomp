#include "asm.h"
#include "log/error.h"
#include "log/logger.h"
#include "main.h"
#include "parseargs.h"
#include "parseobj.h"
#include "preasm.h"
#include "transfer.h"
#include <fcntl.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>

static char *origin;
static uint32_t idx;

static filter
MISC_TXA ()
{
  return (filter)BPF_STMT (BPF_MISC | BPF_TXA, 0);
}

static filter
MISC_TAX ()
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

    case CMP_LT:
      *reverse = !*reverse;
    // fall through
    case CMP_GT:
      return BPF_JGT;

    case CMP_LE:
      *reverse = !*reverse;
    // fall through
    case CMP_GE:
      return BPF_JGE;

    case CMP_AD:
      return BPF_JSET;
    default:
      PEXIT ("%s", INVALID_CMPENUM);
    }
}

static filter
JMP_GOTO (char *clean_line, uint32_t pc)
{
  char *jmp_nr = clean_line + strlen ("goto");

  filter filter = BPF_JUMP (BPF_JMP | BPF_JA, 0, 0, 0);
  char *end;
  filter.k = strtol (jmp_nr, &end, 10) - pc - 1;

  if (jmp_nr == end)
    error ("%d %s", idx, INVALID_NR_AFTER_GOTO);

  return filter;
}

static filter
JMP (char *clean_line, uint32_t pc, uint32_t arch)
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
    error ("%d %s", idx, PAREN_WRAP_CONDITION);

  uint32_t jmp_set = parse_goto (right_paren + 1);
  uint16_t jt = GETJT (jmp_set);
  uint16_t jf = GETJF (jmp_set);

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
    error ("%d %s", idx, INVALID_MEM);
  if (mem_idx >= BPF_MEMWORDS)
    error ("%d %s", idx, INVALID_MEM_IDX);

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

  f_ptr->k = strtol (rval_str, &end, 0);
  if (end == rval_str)
    return false;
  return true;
}

static filter
LD_LDX (char *clean_line, uint32_t arch)
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
    error ("%d %s", idx, INVALID_LEFT_VAR);

  if (LD_LDX_MEM (rval_str, &filter))
    return filter;
  else if (LD_LDX_IMM (rval_str, &filter, arch))
    return filter;

  error ("%d %s", idx, INVALID_LEFT_VAR);
}

static filter
RET (char *clean_line)
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
    error ("%d %s", idx, INVALID_RET);

  return filter;
}

static filter
ST_STX (char *clean_line)
{
  filter filter = { 0, 0, 0, 0 };

  char *idx_str = clean_line + strlen ("$mem[");
  char *end;
  uint32_t idx = strtol (idx_str, &end, 0);
  if (*end != ']')
    error ("%d %s", idx, INVALID_MEM);
  if (*(end + 1) != '=')
    error ("%d %s", idx, INVALID_OPERATOR);
  if (idx >= BPF_MEMWORDS)
    error ("%d %s", idx, INVALID_MEM_IDX);

  filter.k = idx;

  if (*(end + 2) != '$')
    error ("%d %s", INVALID_RIGHT_VAL);

  if (*(end + 3) == 'A')
    filter.code |= BPF_ST;
  else if (*(end + 3) == 'X')
    filter.code |= BPF_STX;
  else
    error ("%d %s", idx, INVALID_RIGHT_VAL);

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
    default:
      PEXIT ("%s", INVALID_ALUENUM);
    }
}

static filter
ALU (char *clean_line)
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
  filter.k = strtol (rval_str, &end, 0);
  if (rval_str == end)
    error ("%d %s", INVALID_RIGHT_VAL);
  return filter;
}

static void
format_print (filter filter, char *format)
{
  uint8_t low_code = filter.code & 0xff;
  uint8_t high_code = (filter.code & ~0xff) / 0x100;
  uint8_t jt = filter.jt;
  uint8_t jf = filter.jf;
  uint8_t k_0 = filter.k & 0xff;
  uint8_t k_1 = (filter.k & ~0xff) / 0x100;
  uint8_t k_2 = (filter.k & ~0xffff) / 0x10000;
  uint8_t k_3 = (filter.k & ~0xffffff) / 0x1000000;

  printf (format, low_code, high_code, jt, jf, k_0, k_1, k_2, k_3);
}

void
assemble (uint32_t arch, FILE *read_fp, print_mode p_mode)
{
  line_set Line;
  fprog prog;
  prog.len = 1;
  prog.filter = malloc (sizeof (filter) * 1024);

  char *format = NULL;
  if (p_mode == HEXFMT)
    format = "\"\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\",\n";
  else if (p_mode == HEXLINE)
    format = "\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x";
  else if (p_mode == RAW)
    format = "%c%c%c%c%c%c%c%c";

  while (pre_asm (read_fp, &Line), Line.origin_line != NULL)
    {
      filter f_current = { 0, 0, 0, 0 };
      char *clean_line = Line.clean_line;
      origin = Line.origin_line;
      idx = prog.len;

      if (!strcmp (clean_line, "$A=$X"))
        f_current = MISC_TXA ();
      else if (!strcmp (clean_line, "$X=$A"))
        f_current = MISC_TAX ();
      else if (STARTWITH (clean_line, "if"))
        f_current = JMP (clean_line, prog.len, arch);
      else if (STARTWITH (clean_line, "goto"))
        f_current = JMP_GOTO (clean_line, prog.len);
      else if (STARTWITH (clean_line, "return"))
        f_current = RET (clean_line);
      else if (STARTWITH (clean_line, "$A=-$A"))
        f_current = ALU (clean_line);
      else if (STARTWITH (clean_line, "$mem["))
        f_current = ST_STX (clean_line);
      else if (STARTWITH (clean_line, "$") && *(clean_line + 2) == '=')
        f_current = LD_LDX (clean_line, arch);
      else if (STARTWITH (clean_line, "$A"))
        f_current = ALU (clean_line);

      prog.filter[prog.len] = f_current;
      format_print (prog.filter[prog.len], format);
      prog.len++;

      free_line(&Line);
    }

  if (p_mode != RAW)
    putchar('\n');
  free (prog.filter);
}
