#include "parsefilter.h"
#include "color.h"
#include "error.h"
#include "transfer.h"
#include <inttypes.h>
#include <linux/bpf_common.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *output_fp;

struct Reg
{
  uint32_t m_arch;
  char *m_str;

  Reg () { m_str = (char *)malloc (0x100); }

  void
  set_val (uint32_t val)
  {
    snprintf (m_str, 0x100, "0x%x", val);
  }

  void
  set_val (char *str)
  {
    snprintf (m_str, 0x100, "%s", str);
  }

  char *
  ret_same_type (char *str)
  {
    uint32_t val = atoi (str);
    return ret_same_type (val);
  }

  char *ret_same_type (uint32_t val);

  char *try_transfer (uint32_t val);
};

char *
Reg::try_transfer (uint32_t val)
{
  char *ret = NULL;
  if (!strcmp (m_str, SYSCALL_NR))
    ret = seccomp_syscall_resolve_num_arch (m_arch, val);
  else if (!strcmp (m_str, ARCHITECTURE))
    {
      ret = ARCH2STR (val);
      if (ret == NULL)
        fprintf (output_fp, "unknown or unsupported architecture: " BLUE_H,
                 val);
    }
  return ret;
}

char *
Reg::ret_same_type (uint32_t val)
{
  char *ret = NULL;
  if (m_str != NULL)
    ret = try_transfer (val);
  // if ret == NULL, the transfer failed or it doesn't need transfer
  // so just transfer the val to str
  if (ret == NULL)
    {
      ret = (char *)malloc (0x20);
      snprintf ((char *)ret, 0x20, "0x%x", val);
    }
  return ret;
}

struct Parser
{
private:
  fprog *m_prog;

  Reg X;
  Reg A;

  Reg mem[BPF_MEMWORDS];

  uint32_t m_arch;

  void LD (filter *f_ptr);

  void LDX (filter *f_ptr);

  void ST (filter *f_ptr);

  void STX (filter *f_ptr);

  void ALU (filter *f_ptr);

  bool JMP (filter *f_ptr, const char *syms[4], int pc);

  void JmpWrap (filter *f_ptr, int pc);

  uint32_t RET (filter *f_ptr);

  void RetWrap (filter *f_ptr);

  void MISC (filter *f_ptr);

public:
  void CLASS (int idx);

  Parser (uint32_t arch, fprog *prog)
  {
    m_prog = prog;
    m_arch = arch;
    A.m_arch = arch;
  }
};

void
Parser::LD (filter *f_ptr)
{
  uint16_t mode = BPF_MODE (f_ptr->code);
  uint32_t k = f_ptr->k;

  switch (mode)
    {
    case BPF_IMM:
      fprintf (output_fp, BLUE_A " = " BLUE_H, k);
      A.set_val (k);
      return;
    case BPF_ABS:
      if (!ABS2STR (k))
        PEXIT (INVALID_OFFSET_ABS ": " BLUE_H, k);
      fprintf (output_fp, BLUE_A " = " BLUE_S, ABS2STR (k));
      A.set_val (ABS2STR (k));
      return;
    case BPF_IND:
      return;
    case BPF_MEM:
      fprintf (output_fp, BLUE_A " = " BLUE_M, k);
      A.set_val (mem[k].m_str);
      return;
    case BPF_LEN:
      fprintf (output_fp, BLUE_A " = " BLUE_H,
               (uint32_t)sizeof (seccomp_data));
      A.set_val (sizeof (seccomp_data));
      return;
    case BPF_MSH:
      return;
    default:
      fprintf (output_fp, "unknown LD: mode: 0x%x", mode);
      exit (0);
    }
}

void
Parser::LDX (filter *f_ptr)
{
  uint16_t mode = BPF_MODE (f_ptr->code);
  uint32_t k = f_ptr->k;

  switch (mode)
    {
    case BPF_IMM:
      fprintf (output_fp, BLUE_X " = " BLUE_H, k);
      X.set_val (k);
      return;
    case BPF_ABS:
      if (!ABS2STR (k))
        PEXIT (INVALID_OFFSET_ABS ": " BLUE_H, k);
      fprintf (output_fp, BLUE_X " = " BLUE_S, ABS2STR (k));
      X.set_val (ABS2STR (k));
      return;
    case BPF_IND:
      return;
    case BPF_MEM:
      fprintf (output_fp, BLUE_X " = " BLUE_M, k);
      X.set_val (mem[k].m_str);
      return;
    case BPF_LEN:
      fprintf (output_fp, BLUE_X " = " BLUE_H,
               (uint32_t)sizeof (seccomp_data));
      X.set_val (sizeof (seccomp_data));
      return;
    case BPF_MSH:
      return;
    default:
      fprintf (output_fp, "unknown LDX: mode: 0x%x", mode);
      exit (0);
    }
}

void
Parser::ST (filter *f_ptr)
{
  fprintf (output_fp, BLUE_M " = " BLUE_A, f_ptr->k);
  mem[f_ptr->k].set_val (A.m_str);
}

void
Parser::STX (filter *f_ptr)
{
  fprintf (output_fp, BLUE_M " = " BLUE_X, f_ptr->k);
  mem[f_ptr->k].set_val (X.m_str);
}

void
Parser::ALU (filter *f_ptr)
{
  uint16_t op = BPF_OP (f_ptr->code);
  uint16_t src = BPF_SRC (f_ptr->code);
  uint32_t k = f_ptr->k;
  char tmp[0x100];

  switch (src)
    {
    case BPF_K:
      switch (op)
        {
        case BPF_ADD:
          snprintf (tmp, 0x100, "(%s += 0x%x)", A.m_str, k);
          fprintf (output_fp, BLUE_A " += " BLUE_H, k);
          A.set_val (tmp);
          return;
        case BPF_SUB:
          snprintf (tmp, 0x100, "(%s -= 0x%x)", A.m_str, k);
          fprintf (output_fp, BLUE_A " -= " BLUE_H, k);
          A.set_val (tmp);
          return;

        case BPF_MUL:
          snprintf (tmp, 0x100, "(%s *= 0x%x)", A.m_str, k);
          fprintf (output_fp, BLUE_A " *= " BLUE_H, k);
          A.set_val (tmp);
          return;

        case BPF_DIV:
          snprintf (tmp, 0x100, "(%s /= 0x%x)", A.m_str, k);
          fprintf (output_fp, BLUE_A " /= " BLUE_H, k);
          A.set_val (tmp);
          return;

        case BPF_AND:
          snprintf (tmp, 0x100, "(%s &= 0x%x)", A.m_str, k);
          fprintf (output_fp, BLUE_A " &= " BLUE_H, k);
          A.set_val (tmp);
          return;

        case BPF_OR:
          snprintf (tmp, 0x100, "(%s |= 0x%x)", A.m_str, k);
          fprintf (output_fp, BLUE_A " |= " BLUE_H, k);
          A.set_val (tmp);
          return;

        case BPF_XOR:
          snprintf (tmp, 0x100, "(%s ^= 0x%x)", A.m_str, k);
          fprintf (output_fp, BLUE_A " ^= " BLUE_H, k);
          A.set_val (tmp);
          return;

        case BPF_MOD:
          snprintf (tmp, 0x100, "(%s %%= 0x%x)", A.m_str, k);
          fprintf (output_fp, BLUE_A " %%= " BLUE_H, k);
          A.set_val (tmp);
          return;

        case BPF_LSH:
          snprintf (tmp, 0x100, "(%s <<= 0x%x)", A.m_str, k);
          fprintf (output_fp, BLUE_A " <<= " BLUE_H, k);
          A.set_val (tmp);
          return;

        case BPF_RSH:
          snprintf (tmp, 0x100, "(%s >>= 0x%x)", A.m_str, k);
          fprintf (output_fp, BLUE_A " >>= " BLUE_H, k);
          A.set_val (tmp);
          return;

          // NEG don't need BPF_K or BPF_X
          // buf BPF_K = 0, so put it here
        case BPF_NEG:
          snprintf (tmp, 0x100, "(-%s)", A.m_str);
          fprintf (output_fp, BLUE_A " = -" BLUE_A);
          A.set_val (tmp);
          return;

        default:
          printf ("unknown alu: op: 0x%x, src: 0x%x", op, src);
          exit (0);
        }
    case BPF_X:
      switch (op)
        {
        case BPF_ADD:
          snprintf (tmp, 0x100, "(%s += %s)", A.m_str, X.m_str);
          fprintf (output_fp, BLUE_A " += " BLUE_S, "$X");
          A.set_val (tmp);
          return;
        case BPF_SUB:
          snprintf (tmp, 0x100, "(%s -= %s)", A.m_str, X.m_str);
          fprintf (output_fp, BLUE_A " -= " BLUE_S, "$X");
          A.set_val (tmp);
          return;
        case BPF_MUL:
          snprintf (tmp, 0x100, "(%s *= %s)", A.m_str, X.m_str);
          fprintf (output_fp, BLUE_A " *= " BLUE_S, "$X");
          A.set_val (tmp);
          return;

        case BPF_DIV:
          snprintf (tmp, 0x100, "(%s /= %s)", A.m_str, X.m_str);
          fprintf (output_fp, BLUE_A " /= " BLUE_S, "$X");
          A.set_val (tmp);
          return;

        case BPF_AND:
          snprintf (tmp, 0x100, "(%s &= %s)", A.m_str, X.m_str);
          fprintf (output_fp, BLUE_A " &= " BLUE_S, "$X");
          A.set_val (tmp);
          return;

        case BPF_OR:
          snprintf (tmp, 0x100, "(%s |= %s)", A.m_str, X.m_str);
          fprintf (output_fp, BLUE_A " |= " BLUE_S, "$X");
          A.set_val (tmp);
          return;

        case BPF_XOR:
          snprintf (tmp, 0x100, "(%s ^= %s)", A.m_str, X.m_str);
          fprintf (output_fp, BLUE_A " ^= " BLUE_S, "$X");
          A.set_val (tmp);
          return;

        case BPF_MOD:
          snprintf (tmp, 0x100, "(%s %%= %s)", A.m_str, X.m_str);
          fprintf (output_fp, BLUE_A " %%= " BLUE_S, "$X");
          A.set_val (tmp);
          return;

        case BPF_LSH:
          snprintf (tmp, 0x100, "(%s >>= %s)", A.m_str, X.m_str);
          fprintf (output_fp, BLUE_A " <<= " BLUE_S, "$X");
          A.set_val (tmp);
          return;

        case BPF_RSH:
          snprintf (tmp, 0x100, "(%s >>= %s)", A.m_str, X.m_str);
          fprintf (output_fp, BLUE_A " >>= " BLUE_S, "$X");
          A.set_val (tmp);
          return;

        default:
          fprintf (output_fp, "unknown alu: op: 0x%x, src: 0x%x", op, src);
          exit (0);
        }
    }
}

bool
Parser::JMP (filter *f_ptr, const char *syms[4], int pc)
{
  uint16_t jmode = BPF_OP (f_ptr->code);
  uint16_t src = BPF_SRC (f_ptr->code);
  uint32_t k = f_ptr->k;

  switch (jmode | src)
    {
    case BPF_JA | BPF_X:
      fprintf (output_fp, "goto " FORMAT, pc + atoi (X.m_str) + 2);
      return false;
    case BPF_JA | BPF_K:
      fprintf (output_fp, "goto " FORMAT, pc + k + 2);
      return false;

    case BPF_JEQ | BPF_X:
      fprintf (output_fp, syms[0], "$X");
      return true;
    case BPF_JEQ | BPF_K:
      fprintf (output_fp, syms[0], A.ret_same_type (k));
      return true;

    case BPF_JGT | BPF_X:
      fprintf (output_fp, syms[1], "$X");
      return true;
    case BPF_JGT | BPF_K:
      fprintf (output_fp, syms[1], A.ret_same_type (k));
      return true;

    case BPF_JGE | BPF_X:
      fprintf (output_fp, syms[2], "$X");
      return true;
    case BPF_JGE | BPF_K:
      fprintf (output_fp, syms[2], A.ret_same_type (k));
      return true;

    case BPF_JSET | BPF_X:
      fprintf (output_fp, syms[3], "$X");
      return true;
    case BPF_JSET | BPF_K:
      fprintf (output_fp, syms[3], A.ret_same_type (k));
      return true;
    default:
      fprintf (output_fp, "unknown jmp: jmode: 0x%x, src: 0x%x", jmode, src);
      exit (0);
    }
}

void
Parser::JmpWrap (filter *f_ptr, int pc)
{
  const char *True[4]
      = { "if (" BLUE_A " == " BLUE_S ") ", "if (" BLUE_A " > " BLUE_S ") ",
          "if (" BLUE_A " >= " BLUE_S ") ", "if (" BLUE_A " & " BLUE_S ") " };
  const char *False[4]
      = { "if (" BLUE_A " != " BLUE_S ") ", "if (" BLUE_A " < " BLUE_S ") ",
          "if (" BLUE_A " <= " BLUE_S ") ", "if !(" BLUE_A " & " BLUE_S ") " };

  uint8_t jt = f_ptr->jt;
  uint8_t jf = f_ptr->jf;

  if (jt == 0 && jf != 0)
    {
      if (JMP (f_ptr, False, pc))
        fprintf (output_fp, "goto " FORMAT, pc + jf + 2);
    }
  else if (jf == 0 && jt != 0)
    {
      if (JMP (f_ptr, True, pc))
        fprintf (output_fp, "goto " FORMAT, pc + jt + 2);
    }
  else
    {
      if (JMP (f_ptr, True, pc))
        fprintf (output_fp, "goto " FORMAT ", else goto " FORMAT, pc + jt + 2,
                 pc + jf + 2);
    }
}

uint32_t
Parser::RET (filter *f_ptr)
{
  uint16_t ret = BPF_RVAL (f_ptr->code);
  char *end;
  uint32_t retval;

  switch (ret)
    {
    case BPF_A:
      retval = strtoul (A.m_str, &end, 0);
      if (A.m_str != end)
        return retval;
      else
        return -1;
    case BPF_K:
      return f_ptr->k;
    default:
      fprintf (output_fp, "unknown ret: 0x%x", ret);
      exit (0);
    }
}

void
Parser::RetWrap (filter *f_ptr)
{
  uint32_t retval = RET (f_ptr);
  char *retstr = RETVAL2STR (retval);

  if (retstr != NULL)
    fprintf (output_fp, "return %s", retstr);
  else
    fprintf (output_fp, "unknown retval: 0x%x", retval);
}

void
Parser::MISC (filter *f_ptr)
{
  uint16_t mode = BPF_MISCOP (f_ptr->code);

  switch (mode)
    {
    case BPF_TAX:
      fprintf (output_fp, BLUE_X " = " BLUE_A);
      X.set_val (A.m_str);
      return;
    case BPF_TXA:
      fprintf (output_fp, BLUE_A " = " BLUE_X);
      A.set_val (X.m_str);
      return;
    default:
      fprintf (output_fp, "unknown mode: 0x%x", mode);
      exit (0);
    }
}

void
Parser::CLASS (int idx)
{
  filter *f_ptr = &m_prog->filter[idx];
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
      JmpWrap (f_ptr, idx);
      return;
    case BPF_RET:
      RetWrap (f_ptr);
      return;
    case BPF_MISC:
      MISC (f_ptr);
      return;
    default:
      fprintf (output_fp, "unknown class: 0x%x", cls);
      exit (0);
    }
}

extern "C"
{
  void
  parse_filter (uint32_t arch, fprog *prog, FILE *output_fileptr)
  {
    output_fp = output_fileptr;

    Parser parser (arch, prog);
    uint32_t len = prog->len;

    fprintf (output_fp, " Line  CODE  JT   JF      K\n");
    fprintf (output_fp, "---------------------------------\n");
    for (uint32_t i = 0; i < len; i++)
      {
        filter *f_ptr = &prog->filter[i];
        fprintf (output_fp, " " FORMAT ": 0x%02x 0x%02x 0x%02x 0x%08x ", i + 1,
                 f_ptr->code, f_ptr->jt, f_ptr->jf, f_ptr->k);
        parser.CLASS (i);
        fprintf (output_fp, "\n");
      }
    fprintf (output_fp, "---------------------------------\n");
  }
}
