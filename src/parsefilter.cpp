#include "parsefilter.h"
#include "color.h"
#include "transfer.h"
#include <cstddef>
#include <inttypes.h>
#include <linux/bpf_common.h>
#include <seccomp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef DEBUG
#define printf_debug(...) printf (__VA_ARGS__)
#endif
#ifndef DEBUG
#define printf_debug(...)
#endif

struct Reg
{
  uint32_t m_arch;
  char *m_str;

  Reg () { m_str = (char *)malloc (0x100); }

  void
  SetVal (const uint32_t val)
  {
    snprintf (m_str, 0x100, "0x%x", val);
  }

  void
  SetVal (const char *str)
  {
    snprintf (m_str, 0x100, "%s", str);
  }

  const char *
  retSameType (const char *const str) const
  {
    uint32_t val = atoi (str);
    return retSameType (val);
  }

  const char *retSameType (uint32_t val) const;

  const char *TryTransfer (uint32_t val) const;
};

const char *
Reg::TryTransfer (uint32_t val) const
{
  const char *ret = NULL;
  if (!strcmp (m_str, syscall_nr))
    ret = seccomp_syscall_resolve_num_arch (m_arch, val);
  else if (!strcmp (m_str, architecture))
    {
      ret = ARCH2STR (val);
      if (ret == NULL)
        printf ("unknown or unsupported architecture: " BLUE_H, val);
    }
  return ret;
}

const char *
Reg::retSameType (uint32_t val) const
{
  const char *ret = NULL;
  if (m_str != NULL)
    ret = TryTransfer (val);
  // if ret == NULL, the transfer failed or it doesn't need transfer
  // so just transfer the val to str
  if (ret == NULL)
    {
      ret = (char *)malloc (0x20);
      snprintf ((char *)ret, 0x20, BLUE_H, val);
    }
  return ret;
}

struct Parser
{
private:
  const fprog *m_prog;

  Reg X;
  Reg A;

  Reg mem[BPF_MEMWORDS];

  uint32_t m_arch;

  void LD (const filter *const f_ptr);

  void LDX (const filter *const f_ptr);

  void ST (const filter *const f_ptr);

  void STX (const filter *const f_ptr);

  void ALU (const filter *const f_ptr);

  bool JMP (const filter *const f_ptr, const char *const syms[4]) const;

  void JmpWrap (const filter *const f_ptr, const int pc) const;

  void RET (const filter *const f_ptr) const;

  void MISC (const filter *const f_ptr);

public:
  void CLASS (const int idx);

  Parser (const uint32_t arch, const fprog *const prog)
  {
    m_prog = prog;
    m_arch = arch;
    A.m_arch = arch;
  }
};

void
Parser::LD (const filter *const f_ptr)
{
  uint16_t mode = BPF_MODE (f_ptr->code);
  uint32_t k = f_ptr->k;

  switch (mode)
    {
    case BPF_IMM:
      printf_debug ("%s: 0x%x\n", "LD | IMM", k);
      printf (BLUE_A " = " BLUE_H, k);
      A.SetVal (k);
      return;
    case BPF_ABS:
      printf_debug ("%s: 0x%x\n", "LD | ABS", k);
      printf (BLUE_A " = " BLUE_S, ABS2STR (k));
      A.SetVal (ABS2STR (k));
      return;
    case BPF_IND:
      printf_debug ("%s: 0x%x\n", "LD | IND", k);
      return;
    case BPF_MEM:
      printf_debug ("%s: 0x%x\n", "LD | MEM", k);
      printf (BLUE_A " = " BLUE ("mem[0x%x]"), k);
      A.SetVal (mem[k].m_str);
      return;
    case BPF_LEN:
      printf_debug ("%s: 0x%x\n", "LD | LEN", k);
      printf (BLUE_A " = " BLUE_H, (uint32_t)sizeof (seccomp_data));
      A.SetVal (sizeof (seccomp_data));
      return;
    case BPF_MSH:
      printf_debug ("%s: 0x%x\n", "LD | MSH", k);
      return;
    default:
      printf ("unknown LD: mode: 0x%x", mode);
    }
}

void
Parser::LDX (const filter *const f_ptr)
{
  uint16_t mode = BPF_MODE (f_ptr->code);
  uint32_t k = f_ptr->k;

  switch (mode)
    {
    case BPF_IMM:
      printf_debug ("%s: 0x%x\n", "LDX | IMM", k);
      printf (BLUE_X " = " BLUE_H, k);
      X.SetVal (k);
      return;
    case BPF_ABS:
      printf_debug ("%s: 0x%x\n", "LDX | ABS", k);
      printf (BLUE_X " = " BLUE_S, ABS2STR (k));
      X.SetVal (ABS2STR (k));
      return;
    case BPF_IND:
      printf_debug ("%s: 0x%x\n", "LDX | IND", k);
      return;
    case BPF_MEM:
      printf_debug ("%s: 0x%x\n", "LDX | MEM", k);
      printf (BLUE_X " = " BLUE ("mem[0x%x]"), k);
      X.SetVal (mem[k].m_str);
      return;
    case BPF_LEN:
      printf_debug ("%s: 0x%x\n", "LDX | LEN", k);
      printf (BLUE_X " = " BLUE_H, (uint32_t)sizeof (seccomp_data));
      X.SetVal (sizeof (seccomp_data));
      return;
    case BPF_MSH:
      printf_debug ("%s: 0x%x\n", "LDX | MSH", k);
      return;
    default:
      printf ("unknown LDX: mode: 0x%x", mode);
    }
}

void
Parser::ST (const filter *const f_ptr)
{
  printf_debug ("%s: %s\n", "ST", A.m_str);
  printf (BLUE ("mem[0x%x]") " = " BLUE_A, f_ptr->k);
  mem[f_ptr->k].SetVal (A.m_str);
}

void
Parser::STX (const filter *const f_ptr)
{
  printf_debug ("%s: %s\n", "STX", X.m_str);
  printf (BLUE ("mem[0x%x]") " = " BLUE_X, f_ptr->k);
  mem[f_ptr->k].SetVal (X.m_str);
}

void
Parser::ALU (const filter *const f_ptr)
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
          printf_debug ("%s: 0x%x\n", "ALU | ADD | BPF_K", k);
          snprintf (tmp, 0x100, "(%s += 0x%x)", A.m_str, k);
          printf (BLUE_A " += " BLUE_H, k);
          A.SetVal (tmp);
          return;
        case BPF_SUB:
          printf_debug ("%s: 0x%x\n", "ALU | SUB | BPF_K", k);
          snprintf (tmp, 0x100, "(%s -= 0x%x)", A.m_str, k);
          printf (BLUE_A " -= " BLUE_H, k);
          A.SetVal (tmp);
          return;

        case BPF_MUL:
          printf_debug ("%s: 0x%x\n", "ALU | MUL | BPF_K", k);
          snprintf (tmp, 0x100, "(%s *= 0x%x)", A.m_str, k);
          printf (BLUE_A " *= " BLUE_H, k);
          A.SetVal (tmp);
          return;

        case BPF_DIV:
          printf_debug ("%s: 0x%x\n", "ALU | DIV | BPF_K", k);
          snprintf (tmp, 0x100, "(%s /= 0x%x)", A.m_str, k);
          printf (BLUE_A " /= " BLUE_H " ", k);
          A.SetVal (tmp);
          return;

        case BPF_AND:
          printf_debug ("%s: 0x%x\n", "ALU | AND | BPF_K", k);
          snprintf (tmp, 0x100, "(%s &= 0x%x)", A.m_str, k);
          printf (BLUE_A " &= " BLUE_H, k);
          A.SetVal (tmp);
          return;

        case BPF_OR:
          printf_debug ("%s: 0x%x\n", "ALU | OR | BPF_K", k);
          snprintf (tmp, 0x100, "(%s |= 0x%x)", A.m_str, k);
          printf (BLUE_A " |= " BLUE_H, k);
          A.SetVal (tmp);
          return;

        case BPF_XOR:
          printf_debug ("%s: 0x%x\n", "ALU | XOR | BPF_K", k);
          snprintf (tmp, 0x100, "(%s ^= 0x%x)", A.m_str, k);
          printf (BLUE_A " ^= " BLUE_H, k);
          A.SetVal (tmp);
          return;

        case BPF_MOD:
          printf_debug ("%s: 0x%x\n", "ALU | MOD | BPF_K", k);
          snprintf (tmp, 0x100, "(%s %%= 0x%x)", A.m_str, k);
          printf (BLUE_A " %%= " BLUE_H, k);
          A.SetVal (tmp);
          return;

        case BPF_LSH:
          printf_debug ("%s: 0x%x\n", "ALU | LSH | BPF_K", k);
          snprintf (tmp, 0x100, "(%s <<= 0x%x)", A.m_str, k);
          printf (BLUE_A " <<= " BLUE_H, k);
          A.SetVal (tmp);
          return;

        case BPF_RSH:
          printf_debug ("%s: 0x%x\n", "ALU | RSH | BPF_K", k);
          snprintf (tmp, 0x100, "(%s >>= 0x%x)", A.m_str, k);
          printf (BLUE_A " >>= " BLUE_H, k);
          A.SetVal (tmp);
          return;

          // NEG don't need BPF_K or BPF_X
          // buf BPF_K = 0, so put it here
        case BPF_NEG:
          printf_debug ("%s\n", "BPF_NEG");
          snprintf (tmp, 0x100, "(-%s)", A.m_str);
          printf (BLUE_A " = " BLUE ("-A"));
          A.SetVal (tmp);
          return;

        default:
          printf ("unknown alu: op: 0x%x, src: 0x%x", op, src);
          return;
        }
    case BPF_X:
      switch (op)
        {
        case BPF_ADD:
          printf_debug ("%s: %s\n", "ALU | ADD | BPF_X", X.m_str);
          snprintf (tmp, 0x100, "(%s += %s)", A.m_str, X.m_str);
          printf (BLUE_A " += " BLUE_S, X.m_str);
          A.SetVal (tmp);
          return;
        case BPF_SUB:
          printf_debug ("%s: %s\n", "ALU | SUB | BPF_X", X.m_str);
          snprintf (tmp, 0x100, "(%s -= %s)", A.m_str, X.m_str);
          printf (BLUE_A " -= " BLUE_S, X.m_str);
          A.SetVal (tmp);
          return;
        case BPF_MUL:
          printf_debug ("%s: %s\n", "ALU | MUL | BPF_X", X.m_str);
          snprintf (tmp, 0x100, "(%s *= %s)", A.m_str, X.m_str);
          printf (BLUE_A " *= " BLUE_S, X.m_str);
          A.SetVal (tmp);
          return;

        case BPF_DIV:
          printf_debug ("%s: %s\n", "ALU | DIV | BPF_X", X.m_str);
          snprintf (tmp, 0x100, "(%s /= %s)", A.m_str, X.m_str);
          printf (BLUE_A " /= " BLUE_S, X.m_str);
          A.SetVal (tmp);
          return;

        case BPF_AND:
          printf_debug ("%s: %s\n", "ALU | AND | BPF_X", X.m_str);
          snprintf (tmp, 0x100, "(%s &= %s)", A.m_str, X.m_str);
          printf (BLUE_A " &= " BLUE_S, X.m_str);
          A.SetVal (tmp);
          return;

        case BPF_OR:
          printf_debug ("%s: %s\n", "ALU | OR | BPF_X", X.m_str);
          snprintf (tmp, 0x100, "(%s |= %s)", A.m_str, X.m_str);
          printf (BLUE_A " |= " BLUE_S, X.m_str);
          A.SetVal (tmp);
          return;

        case BPF_XOR:
          printf_debug ("%s: %s\n", "ALU | XOR | BPF_X", X.m_str);
          snprintf (tmp, 0x100, "(%s ^= %s)", A.m_str, X.m_str);
          printf (BLUE_A " ^= " BLUE_S, X.m_str);
          A.SetVal (tmp);
          return;

        case BPF_MOD:
          printf_debug ("%s: %s\n", "ALU | MOD | BPF_X", X.m_str);
          snprintf (tmp, 0x100, "(%s %%= %s)", A.m_str, X.m_str);
          printf (BLUE_A " %%= " BLUE_S, X.m_str);
          A.SetVal (tmp);
          return;

        case BPF_LSH:
          printf_debug ("%s: %s\n", "ALU | LSH | BPF_X", X.m_str);
          snprintf (tmp, 0x100, "(%s <<= %s)", A.m_str, X.m_str);
          printf (BLUE_A " <<= " BLUE_S, X.m_str);
          A.SetVal (tmp);
          return;

        case BPF_RSH:
          printf_debug ("%s: %s\n", "ALU | RSH | BPF_X", X.m_str);
          snprintf (tmp, 0x100, "(%s >>= %s)", A.m_str, X.m_str);
          printf (BLUE_A " >>= " BLUE_S, X.m_str);
          A.SetVal (tmp);
          return;

        default:
          printf ("unknown alu: op: 0x%x, src: 0x%x", op, src);
        }
    }
}

bool
Parser::JMP (const filter *const f_ptr, const char *const syms[4]) const
{
  uint16_t jmode = BPF_OP (f_ptr->code);
  uint16_t src = BPF_SRC (f_ptr->code);
  uint32_t k = f_ptr->k;

  switch (jmode | src)
    {
    case BPF_JA | BPF_X:
      printf_debug ("%s: %0004d\n", "JMP | JA | BPF_X", atoi (X.m_str));
      printf ("goto %s", X.m_str);
      return false;
    case BPF_JA | BPF_K:
      printf_debug ("%s: %0004d\n", "JMP | JA | BPF_K", k);
      printf ("goto 0x%x", k);
      return false;

    case BPF_JEQ | BPF_X:
      printf_debug ("%s: 0x%x\n", "JMP | JEQ | BPF_X", atoi (X.m_str));
      printf (syms[0], A.retSameType (X.m_str));
      return true;
    case BPF_JEQ | BPF_K:
      printf_debug ("%s: 0x%x\n", "JMP | JEQ | BPF_K", k);
      printf (syms[0], A.retSameType (k));
      return true;

    case BPF_JGT | BPF_X:
      printf_debug ("%s: 0x%x\n", "JMP | JGT | BPF_X", atoi (X.m_str));
      printf (syms[1], A.retSameType (X.m_str));
      return true;
    case BPF_JGT | BPF_K:
      printf_debug ("%s: 0x%x\n", "JMP | JGT | BPF_K", k);
      printf (syms[1], A.retSameType (k));
      return true;

    case BPF_JGE | BPF_X:
      printf_debug ("%s: 0x%x\n", "JMP | JGE | BPF_X", atoi (X.m_str));
      printf (syms[2], A.retSameType (X.m_str));
      return true;
    case BPF_JGE | BPF_K:
      printf_debug ("%s: 0x%x\n", "JMP | JGE | BPF_K", k);
      printf (syms[2], A.retSameType (k));
      return true;

    case BPF_JSET | BPF_X:
      printf_debug ("%s: 0x%x\n", "JMP | JSET | BPF_X", atoi (X.m_str));
      printf (syms[3], A.retSameType (X.m_str));
      return true;
    case BPF_JSET | BPF_K:
      printf_debug ("%s: 0x%x\n", "JMP | JSET | BPF_K", k);
      printf (syms[3], A.retSameType (k));
      return true;
    default:
      printf ("unknown jmp: jmode: 0x%x, src: 0x%x", jmode, src);
      return false;
    }
}

void
Parser::JmpWrap (const filter *const f_ptr, const int pc) const
{
  const char *const True[4]
      = { "if (" BLUE_A " == " BLUE_S ") ", "if (" BLUE_A " > " BLUE_S ") ",
          "if (" BLUE_A " >= " BLUE_S ") ", "if (" BLUE_A " & " BLUE_S ") " };
  const char *const False[4]
      = { "if (" BLUE_A " != " BLUE_S ") ", "if (" BLUE_A " <= " BLUE_S ") ",
          "if (" BLUE_A " < " BLUE_S ") ", "if !(" BLUE_A "& " BLUE_S ") " };

  uint8_t jt = f_ptr->jt;
  uint8_t jf = f_ptr->jf;

  if (jt == 0 && jf != 0)
    {
      if (JMP (f_ptr, False))
        printf ("goto %0004d", pc + jf + 1);
    }
  else if (jf == 0 && jt != 0)
    {
      if (JMP (f_ptr, True))
        printf ("goto %0004d", pc + jt + 1);
    }
  else
    {
      if (JMP (f_ptr, True))
        printf ("goto %0004d, else goto %0004d", pc + jt + 1, pc + jf + 1);
    }
}

void
Parser::RET (const filter *const f_ptr) const
{
  uint16_t ret = BPF_RVAL (f_ptr->code);

  switch (ret)
    {
    case BPF_A:
      printf_debug ("%s: %s\n", "RET | BPF_A", A.m_str);
      printf ("ret %s", RETVAL2STR (atoi (A.m_str)));
      return;
    case BPF_K:
      printf_debug ("%s: 0x%x\n", "RET | BPF_K", f_ptr->k);
      printf ("ret %s", RETVAL2STR (f_ptr->k));
      return;
    default:
      printf ("unknown ret: 0x%x", ret);
    }
}

void
Parser::MISC (const filter *const f_ptr)
{
  uint16_t mode = BPF_MISCOP (f_ptr->code);

  switch (mode)
    {
    case BPF_TAX:
      printf_debug ("%s: A: %s, X: %s\n", "MISC | TAX", A.m_str, X.m_str);
      printf (BLUE_A " = " BLUE_X);
      X.SetVal (A.m_str);
      return;
    case BPF_TXA:
      printf_debug ("%s: A: %s, X: %s\n", "MISC | TXA", A.m_str, X.m_str);
      printf (BLUE_A " = " BLUE_X);
      A.SetVal (1);
      return;
    default:
      printf ("unknown mode: 0x%x", mode);
    }
}

void
Parser::CLASS (const int idx)
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
      RET (f_ptr);
      return;
    case BPF_MISC:
      MISC (f_ptr);
      return;
    default:
      printf ("unknown class: 0x%x", cls);
    }
}

extern "C"
{
  void
  ParseFilter (uint32_t arch, const fprog *const prog)
  {
    Parser parser (arch, prog);
    uint32_t len = prog->len;

    printf (" Line  CODE  JT   JF      K\n");
    printf ("---------------------------------\n");
    for (uint32_t i = 0; i < len; i++)
      {
        filter *f_ptr = &prog->filter[i];
        printf (" %04d: 0x%02x 0x%02x 0x%02x 0x%08x ", i, f_ptr->code,
                f_ptr->jt, f_ptr->jf, f_ptr->k);
        parser.CLASS (i);
        printf ("\n");
      }
  }
}
