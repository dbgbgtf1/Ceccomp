#include "asm.h"
#include "error.h"
#include "main.h"
#include "parseargs.h"
#include "parseobj.h"
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
jmp_mode (uint8_t sym_enum, bool *reverse, char *origin_line)
{
  switch (sym_enum)
    {
    case SYM_NE:
      *reverse = !*reverse;
    case SYM_EQ:
      return BPF_JEQ;

    case SYM_LT:
      *reverse = !*reverse;
    case SYM_GT:
      return BPF_JGT;

    case SYM_LE:
      *reverse = !*reverse;
    case SYM_GE:
      return BPF_JGE;

    case SYM_AD:
      return BPF_JSET;
    default:
      PEXIT (INVALID_SYMENUM ": %d", sym_enum);
    }
}

static void
jmp_src (char *rval, filter *f_ptr, uint32_t arch, char *origin_line)
{
  f_ptr->k = STR2ARCH (rval);
  if (f_ptr->k != -1)
    {
      f_ptr->code |= BPF_K;
      return;
    }

  char *syscall_name = strndup (rval, strchr (rval, ')') - rval);
  f_ptr->k = seccomp_syscall_resolve_name_arch (arch, syscall_name);
  if (f_ptr->k != __NR_SCMP_ERROR)
    {
      free (syscall_name);
      f_ptr->code |= BPF_K;
      return;
    }
  free (syscall_name);

  char *end;
  f_ptr->k = strtol (rval, &end, 0);
  if (rval != end)
    {
      f_ptr->code |= BPF_K;
      return;
    }

  if (!STARTWITH (rval, "$X"))
    PEXIT (INVALID_RIGHT ": %s", origin_line);

  f_ptr->code |= BPF_X;
}

static filter
JMP (line_set *Line, uint32_t pc, uint32_t arch)
{
  char *clean_line = Line->clean_line;
  char *origin_line = Line->origin_line;
  filter filter = BPF_JUMP (BPF_JMP, 0, 0, 0);

  bool reverse = maybe_reverse (clean_line, origin_line);
  char *sym_str;
  if (reverse)
    sym_str = clean_line + strlen ("if!($A");
  else
    sym_str = clean_line + strlen ("if($A");

  uint8_t sym_enum = parse_compare_sym (sym_str, origin_line);
  uint8_t sym_len = GETSYMLEN (sym_enum);

  filter.code |= jmp_mode (sym_enum, &reverse, origin_line);

  char *rval = sym_str + sym_len;
  jmp_src (rval, &filter, arch, origin_line);

  char *right_brace = strchr (rval, ')');
  uint16_t jmpset = parse_goto (right_brace, origin_line);

  uint8_t jt = GETJT (jmpset);
  uint8_t jf = GETJF (jmpset);

  if (reverse)
    {
      filter.jt = jt ? (jt - pc - 1) : 0;
      filter.jf = jf ? (jf - pc - 1) : 0;
    }
  else
    {
      filter.jt = jf ? (jf - pc - 1) : 0;
      filter.jf = jt ? (jt - pc - 1) : 0;
    }

  return filter;
}

static bool
LD_LDX_ABS (char *rvar, filter *f_ptr)
{
  uint32_t offset = STR2ABS (rvar);
  if (offset == -1)
    return false;

  f_ptr->code |= (BPF_W | BPF_ABS);
  f_ptr->k = offset;
  return true;
}

static bool
LD_LDX_MEM (char *rvar, filter *f_ptr, char *origin_line)
{
  char *end;
  if (!STARTWITH (rvar, "$mem["))
    return false;

  rvar += strlen ("$mem[");
  uint32_t mem_idx = strtol (rvar, &end, 0);

  if (*end != ']')
    PEXIT (INVALID_MEM ": %s", origin_line);
  if (mem_idx > 15)
    PEXIT (INVALID_MEM_IDX ": %s", origin_line);

  f_ptr->code |= BPF_MEM;
  f_ptr->k = mem_idx;
  return true;
}

static bool
LD_LDX_IMM (char *rvar, filter *f_ptr, uint32_t arch, char *origin_line)
{
  char *end;
  f_ptr->code |= BPF_IMM;
  f_ptr->k = seccomp_syscall_resolve_name_arch (arch, rvar);
  if (f_ptr->k != __NR_SCMP_ERROR)
    return true;

  f_ptr->k = strtol (rvar, &end, 0);
  if (end == rvar)
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

  if (*(clean_line + 2) != '=')
    PEXIT (INVALID_OPERATOR ": %s", origin_line);

  char *rvar = clean_line + 3;
  if (LD_LDX_ABS (rvar, &filter))
    return filter;
  else if (LD_LDX_MEM (rvar, &filter, origin_line))
    return filter;
  else if (LD_LDX_IMM (rvar, &filter, arch, origin_line))
    return filter;
  PEXIT (INVALID_RIGHT ": %s", origin_line);
}

static filter
RET (line_set *Line)
{
  char *clean_line = Line->clean_line;
  char *origin_line = Line->origin_line;
  filter filter = { BPF_RET, 0, 0, 0 };

  char *retval_str = STRAFTER (clean_line, "return");

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

  char *idx_str = STRAFTER (clean_line, "$mem[");
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
    PEXIT (INVALID_RIGHT_VAR ": %s", origin_line);
  if (*(end + 3) == 'A')
    filter.code |= BPF_A;
  if (*(end + 3) == 'X')
    filter.code |= BPF_X;
  else
    PEXIT (INVALID_RIGHT_VAR ": %s", origin_line);

  return filter;
}

static void
rawbytes (filter filter)
{
  uint16_t code = filter.code;
  uint8_t jf = filter.jf;
  uint8_t jt = filter.jt;
  uint32_t k = filter.k;

  printf ("%c%c%c%c", code & 0xff00, code & 0xff, jf, jt);
  printf ("%c%c%c%c", (k & 0xff000000) / 0x1000000, (k & 0xff0000) / 0x10000,
          (k & 0xff00) / 0x100, k & 0xff);
}

static void
hexline (filter filter)
{
  uint16_t code = filter.code;
  uint8_t jf = filter.jf;
  uint8_t jt = filter.jt;
  uint32_t k = filter.k;

  printf ("\\x%02x\\x%02x\\x%02x\\x%02x", code & 0xff00, code & 0xff, jf, jt);
  printf ("\\x%02x\\x%02x\\x%02x\\x%02x", (k & 0xff000000) / 0x1000000,
          (k & 0xff0000) / 0x10000, (k & 0xff00) / 0x100, k & 0xff);
}

static void
hexfmt (filter filter)
{
  uint16_t code = filter.code;
  uint8_t jf = filter.jf;
  uint8_t jt = filter.jt;
  uint32_t k = filter.k;

  printf ("\\x%02x\\x%02x\\x%02x\\x%02x", code & 0xff00, code & 0xff, jf, jt);
  printf ("\\x%02x\\x%02x\\x%02x\\x%02x\n", (k & 0xff000000) / 0x1000000,
          (k & 0xff0000) / 0x10000, (k & 0xff00) / 0x100, k & 0xff);
}

static void
asm_lines (FILE *fp, unsigned arch, uint32_t print_mode)
{
  line_set Line;
  fprog *prog = malloc (sizeof (fprog));
  prog->len = 1;
  prog->filter = malloc (sizeof (filter) * 0x100);

  while (pre_asm (fp, &Line), Line.origin_line != NULL)
    {
      filter f_current;
      char *clean_line = Line.clean_line;
      char *origin_line = Line.origin_line;

      if (!strcmp (clean_line, "$A=$X"))
        f_current = MISC_TXA ();
      else if (!strcmp (clean_line, "$X=$A"))
        f_current = MISC_TAX ();
      else if (STARTWITH (clean_line, "if"))
        f_current = JMP (&Line, prog->len, arch);
      else if (STARTWITH (clean_line, "return"))
        f_current = RET (&Line);
      else if (STARTWITH (clean_line, "$mem["))
        f_current = ST_STX (&Line);
      else if (STARTWITH (clean_line, "$"))
        f_current = LD_LDX (&Line, arch);

      prog->filter[prog->len] = f_current;
      prog->len++;
    }

  if (print_mode == HEXFMT)
    for (int i = 1; i < prog->len; i++)
      hexfmt (prog->filter[i]);
  else if (print_mode == HEXLINE)
    for (int i = 1; i < prog->len; i++)
      hexline (prog->filter[i]);
  else if (print_mode == RAW)
    for (int i = 1; i < prog->len; i++)
      rawbytes (prog->filter[i]);

  free (prog->filter);
  free (prog);
}

void
assemble (int argc, char *argv[])
{
  char *filename = get_arg (argc, argv);
  FILE *fp = fopen (filename, "r");
  if (fp == NULL)
    PEXIT (UNABLE_OPEN_FILE ": %s", filename);

  char *arch_str = parse_option (argc, argv, "arch");
  uint32_t arch = STR2ARCH (arch_str);
  if (arch == -1)
    PEXIT (INVALID_ARCH ": %s\n" SUPPORT_ARCH, arch_str);

  char *print_mode_str = parse_option (argc, argv, "fmt");
  uint32_t print_mode;
  if (print_mode_str == NULL || !strcmp (print_mode_str, "hexline"))
    print_mode = HEXLINE;
  else if (!strcmp (print_mode_str, "hexfmt"))
    print_mode = HEXFMT;
  else if (!strcmp (print_mode_str, "raw"))
    print_mode = RAW;
  else
    PEXIT (INVALID_PRINT_MODE ": %s", print_mode_str);

  asm_lines (fp, arch, print_mode);
}
