#include "asm.h"
#include "error.h"
#include "main.h"
#include "parseargs.h"
#include "parseobj.h"
#include "preasm.h"
#include "transfer.h"
#include <fcntl.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>

static filter MISC_TXA ();

static filter MISC_TAX ();

static uint16_t jmp_mode (uint8_t sym_enum, bool *reverse, char *origin_line);

static void jmp_src (char *rval, filter *f_ptr, uint32_t arch,
                     char *origin_line);

static filter JMP_GOTO (line_set *Line, uint32_t pc);

static filter JMP (line_set *Line, uint32_t pc, uint32_t arch);

static bool LD_LDX_ABS (char *rval, filter *f_ptr);

static bool LD_LDX_MEM (char *rval, filter *f_ptr, char *origin_line);

static bool LD_LDX_IMM (char *rval, filter *f_ptr, uint32_t arch,
                        char *origin_line);

static filter LD_LDX (line_set *Line, uint32_t arch);

static filter RET (line_set *Line);

static filter ST_STX (line_set *Line);

static void format_print (filter filter, char *format);

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

// comparing the sym
// also EQ and NE can be the same thing
// only you have to reverse
static uint16_t
jmp_mode (uint8_t cmp_enum, bool *reverse, char *origin_line)
{
  switch (cmp_enum)
    {
    case CMP_NE:
      *reverse = !*reverse;
    case CMP_EQ:
      return BPF_JEQ;

    case CMP_LT:
      *reverse = !*reverse;
    case CMP_GT:
      return BPF_JGT;

    case CMP_LE:
      *reverse = !*reverse;
    case CMP_GE:
      return BPF_JGE;

    case CMP_AD:
      return BPF_JSET;
    default:
      PEXIT (INVALID_CMPENUM ": %d\n: %s", cmp_enum, origin_line);
    }
}

static filter
JMP_GOTO (line_set *Line, uint32_t pc)
{
  char *clean_line = Line->clean_line;
  char *jmp_nr = clean_line + strlen ("goto");

  filter filter = BPF_JUMP (BPF_JMP | BPF_JA, 0, 0, 0);
  char *end;
  filter.k = strtol (jmp_nr, &end, 10) - pc - 1;

  if (jmp_nr == end)
    PEXIT (INVALID_NR_AFTER_GOTO ": %s", Line->origin_line);

  return filter;
}

static filter
JMP (line_set *Line, uint32_t pc, uint32_t arch)
{
  char *clean_line = Line->clean_line;
  char *origin_line = Line->origin_line;
  filter filter = BPF_JUMP (BPF_JMP, 0, 0, 0);

  bool reverse = maybe_reverse (clean_line, origin_line);
  char *cmp_str;
  if (reverse)
    cmp_str = clean_line + strlen ("if!($A");
  else
    cmp_str = clean_line + strlen ("if($A");

  uint8_t sym_enum = parse_cmp_sym (cmp_str, origin_line);
  uint8_t sym_len = GETSYMLEN (sym_enum);

  filter.code |= jmp_mode (sym_enum, &reverse, origin_line);

  char *rval = cmp_str + sym_len;
  if (STARTWITH (rval, "$X"))
    filter.code |= BPF_X;
  else
    {
      filter.code |= BPF_K;
      filter.k |= right_val_ifline (rval, NULL, arch, origin_line);
    }

  char *right_brace = strchr (rval, ')');
  if (right_brace == NULL)
    PEXIT (BRACE_WRAP_CONDITION ": %s", origin_line);

  uint32_t jmp_set = parse_goto (right_brace + 1, origin_line);
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
LD_LDX_ABS (char *rval, filter *f_ptr)
{
  uint32_t offset = STR2ABS (rval);
  if (offset == -1)
    return false;

  f_ptr->code |= (BPF_W | BPF_ABS);
  f_ptr->k = offset;
  return true;
}

static bool
LD_LDX_MEM (char *rval, filter *f_ptr, char *origin_line)
{
  char *end;
  if (!STARTWITH (rval, "$mem["))
    return false;

  rval += strlen ("$mem[");
  uint32_t mem_idx = strtol (rval, &end, 0);

  if (*end != ']')
    PEXIT (INVALID_MEM ": %s", origin_line);
  if (mem_idx > 15)
    PEXIT (INVALID_MEM_IDX ": %s", origin_line);

  f_ptr->code |= BPF_MEM;
  f_ptr->k = mem_idx;
  return true;
}

static bool
LD_LDX_IMM (char *rval, filter *f_ptr, uint32_t arch, char *origin_line)
{
  char *end;
  f_ptr->code |= BPF_IMM;
  f_ptr->k = seccomp_syscall_resolve_name_arch (arch, rval);
  if (f_ptr->k != __NR_SCMP_ERROR)
    return true;

  f_ptr->k = strtol (rval, &end, 0);
  if (end == rval)
    return false;
  return true;
}

static filter
LD_LDX (line_set *Line, uint32_t arch)
{
  char *clean_line = Line->clean_line;
  char *origin_line = Line->origin_line;

  filter filter = { 0, 0, 0, 0 };
  if (*(clean_line + 1) == 'A')
    filter.code |= BPF_LD;
  else if (*(clean_line + 1) == 'X')
    filter.code |= BPF_LDX;
  else
    PEXIT (INVALID_LEFT_VAR ": %s", origin_line);

  char *rval = clean_line + 3;
  if (LD_LDX_ABS (rval, &filter))
    return filter;
  else if (LD_LDX_MEM (rval, &filter, origin_line))
    return filter;
  else if (LD_LDX_IMM (rval, &filter, arch, origin_line))
    return filter;
  PEXIT (INVALID_RIGHT ": %s", origin_line);
}

static filter
RET (line_set *Line)
{
  char *clean_line = Line->clean_line;
  char *origin_line = Line->origin_line;
  filter filter = { BPF_RET, 0, 0, 0 };

  char *retval_str = clean_line + strlen ("return");

  uint32_t retval = STR2RETVAL (retval_str);
  if (retval != -1)
    {
      filter.code |= BPF_K;
      filter.k |= retval;
    }
  else if (STARTWITH (retval_str, "$A"))
    filter.code |= BPF_A;
  else
    PEXIT (INVALID_RET ": %s", origin_line);

  return filter;
}

static filter
ST_STX (line_set *Line)
{
  char *clean_line = Line->clean_line;
  char *origin_line = Line->origin_line;
  filter filter = { 0, 0, 0, 0 };

  char *idx_str = clean_line + strlen ("$mem[");
  char *end;
  uint32_t idx = strtol (idx_str, &end, 0);
  if (*end != ']')
    PEXIT (INVALID_MEM ": %s", origin_line);
  if (*(end + 1) != '=')
    PEXIT (INVALID_OPERATOR ": %s", origin_line);
  if (idx > 15)
    PEXIT (INVALID_MEM_IDX ": %s", origin_line);

  filter.k = idx;

  if (*(end + 2) != '$')
    PEXIT (INVALID_RIGHT ": %s", origin_line);
  if (*(end + 3) == 'A')
    filter.code |= BPF_A;
  if (*(end + 3) == 'X')
    filter.code |= BPF_X;
  else
    PEXIT (INVALID_RIGHT ": %s", origin_line);

  return filter;
}

static uint16_t
alu_mode (uint8_t alu_enum, char *origin_line)
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
    case ALU_NG:
      return BPF_NEG;
    case ALU_LS:
      return BPF_LSH;
    case ALU_RS:
      return BPF_RSH;
    default:
      PEXIT (INVALID_ALUENUM ": %d\n: %s", alu_enum, origin_line);
    }
}

static filter
ALU (line_set *Line)
{
  char *clean_line = Line->clean_line;
  char *origin_line = Line->origin_line;
  filter filter = BPF_STMT (BPF_ALU, 0);

  char *sym_str = clean_line + strlen ("$A");
  uint8_t sym_enum = parse_alu_sym (sym_str, clean_line);
  uint8_t sym_len = GETSYMLEN (sym_enum);

  filter.code |= alu_mode (sym_enum, origin_line);

  char *rval_str = sym_str + sym_len;
  if (!strcmp (rval_str, "$X"))
    {
      filter.k = BPF_X;
      return filter;
    }

  char *end;
  filter.k = strtol (rval_str, &end, 0);
  if (rval_str == end)
    PEXIT (INVALID_RIGHT_VALUE ": %s", origin_line);
  return filter;
}

static void
format_print (filter filter, char *format)
{
  uint8_t low_code = filter.code & 0xff;
  uint8_t high_code = (filter.code & 0xff00) / 0x100;
  uint8_t jt = filter.jt;
  uint8_t jf = filter.jf;
  uint8_t k_0 = filter.k & 0xff;
  uint8_t k_1 = (filter.k & ~0xff) / 0x100;
  uint8_t k_2 = (filter.k & ~0xffff) / 0x10000;
  uint8_t k_3 = (filter.k & ~0xffffff) / 0x1000000;

  printf (format, low_code, high_code, jt, jf, k_0, k_1, k_2, k_3);
}

void
assemble (uint32_t arch, FILE *read_fp, uint32_t print_mode)
{
  line_set Line;
  fprog prog;
  prog.len = 1;
  prog.filter = malloc (sizeof (filter) * 1024);

  while (pre_asm (read_fp, &Line), Line.origin_line != NULL)
    {
      filter f_current;
      char *clean_line = Line.clean_line;
      char *origin_line = Line.origin_line;

      if (!strcmp (clean_line, "$A=$X"))
        f_current = MISC_TXA ();
      else if (!strcmp (clean_line, "$X=$A"))
        f_current = MISC_TAX ();
      else if (STARTWITH (clean_line, "if"))
        f_current = JMP (&Line, prog.len, arch);
      else if (STARTWITH (clean_line, "goto"))
        f_current = JMP_GOTO (&Line, prog.len);
      else if (STARTWITH (clean_line, "return"))
        f_current = RET (&Line);
      else if (STARTWITH (clean_line, "$mem["))
        f_current = ST_STX (&Line);
      else if (STARTWITH (clean_line, "$") && *(clean_line + 2) == '=')
        f_current = LD_LDX (&Line, arch);
      else if (STARTWITH (clean_line, "$A"))
        f_current = ALU (&Line);

      prog.filter[prog.len] = f_current;
      prog.len++;
    }

  char *format = NULL;
  if (print_mode == HEXFMT)
    format = "\"\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\",\n";
  else if (print_mode == HEXLINE)
    format = "\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x";
  else if (print_mode == RAW)
    format = "%c%c%c%c%c%c%c%c";

  for (int i = 1; i < prog.len; i++)
    format_print (prog.filter[i], format);

  printf ("\n");
  free (prog.filter);
}
