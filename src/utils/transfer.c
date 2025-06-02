#include "transfer.h"
#include "color.h"
#include "emu.h"
#include "main.h"
#include <linux/filter.h>
#include <seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *
ARCH2STR (uint32_t token)
{
  switch (token)
    {
    case SCMP_ARCH_X86:
      return STR_ARCH_X86;
    case SCMP_ARCH_X86_64:
      return STR_ARCH_X86_64;

    case SCMP_ARCH_X32:
      return STR_ARCH_X32;

    case SCMP_ARCH_ARM:
      return STR_ARCH_ARM;
    case SCMP_ARCH_AARCH64:
      return STR_ARCH_AARCH64;

    case SCMP_ARCH_MIPS:
      return STR_ARCH_MIPS;
    case SCMP_ARCH_MIPSEL:
      return STR_ARCH_MIPSEL;
    case SCMP_ARCH_MIPS64:
      return STR_ARCH_MIPS64;
    case SCMP_ARCH_MIPSEL64:
      return STR_ARCH_MIPSEL64;
    case SCMP_ARCH_MIPS64N32:
      return STR_ARCH_MIPS64N32;
    case SCMP_ARCH_MIPSEL64N32:
      return STR_ARCH_MIPSEL64N32;

    case SCMP_ARCH_PARISC:
      return STR_ARCH_PARISC;
    case SCMP_ARCH_PARISC64:
      return STR_ARCH_PARISC64;

    case SCMP_ARCH_PPC:
      return STR_ARCH_PPC;
    case SCMP_ARCH_PPC64:
      return STR_ARCH_PPC64;
    case SCMP_ARCH_PPC64LE:
      return STR_ARCH_PPC64LE;

    case SCMP_ARCH_S390:
      return STR_ARCH_S390;
    case SCMP_ARCH_S390X:
      return STR_ARCH_S390X;

    case SCMP_ARCH_RISCV64:
      return STR_ARCH_RISCV64;
    default:
      return NULL;
    }
}

uint32_t
STR2ARCH (char *arch)
{
  if (STARTWITH (arch, STR_ARCH_X86))
    return SCMP_ARCH_X86;
  else if (STARTWITH (arch, STR_ARCH_X86_64))
    return SCMP_ARCH_X86_64;

  else if (STARTWITH (arch, STR_ARCH_X32))
    return SCMP_ARCH_X32;

  else if (STARTWITH (arch, STR_ARCH_ARM))
    return SCMP_ARCH_ARM;
  else if (STARTWITH (arch, STR_ARCH_AARCH64))
    return SCMP_ARCH_AARCH64;

  else if (STARTWITH (arch, STR_ARCH_MIPS))
    return SCMP_ARCH_MIPS;
  else if (STARTWITH (arch, STR_ARCH_MIPSEL))
    return SCMP_ARCH_MIPSEL;
  else if (STARTWITH (arch, STR_ARCH_MIPS64))
    return SCMP_ARCH_MIPS64;
  else if (STARTWITH (arch, STR_ARCH_MIPSEL64))
    return SCMP_ARCH_MIPSEL64;
  else if (STARTWITH (arch, STR_ARCH_MIPS64N32))
    return SCMP_ARCH_MIPS64N32;
  else if (STARTWITH (arch, STR_ARCH_MIPSEL64N32))
    return SCMP_ARCH_MIPSEL64N32;

  else if (STARTWITH (arch, STR_ARCH_PARISC))
    return SCMP_ARCH_PARISC;
  else if (STARTWITH (arch, STR_ARCH_PARISC64))
    return SCMP_ARCH_PARISC64;

  else if (STARTWITH (arch, STR_ARCH_PPC))
    return SCMP_ARCH_PPC;
  else if (STARTWITH (arch, STR_ARCH_PPC64))
    return SCMP_ARCH_PPC64;
  else if (STARTWITH (arch, STR_ARCH_PPC64LE))
    return SCMP_ARCH_PPC64LE;

  else if (STARTWITH (arch, STR_ARCH_S390))
    return SCMP_ARCH_S390;
  else if (STARTWITH (arch, STR_ARCH_S390X))
    return SCMP_ARCH_S390X;

  else if (STARTWITH (arch, STR_ARCH_RISCV64))
    return SCMP_ARCH_RISCV64;
  else
    return -1;
}

char *
ABS2STR (uint32_t offset)
{
  switch (offset)
    {
    case offsetof (seccomp_data, nr):
      return SYSCALL_NR;
    case offsetof (seccomp_data, arch):
      return ARCHITECTURE;

    case offsetof (seccomp_data, instruction_pointer):
      return LOW_PC;
    case offsetof (seccomp_data, instruction_pointer) + 4:
      return HIGH_PC;

    case offsetof (seccomp_data, args[0]):
      return LOW_ARG0;
    case offsetof (seccomp_data, args[1]):
      return LOW_ARG1;
    case offsetof (seccomp_data, args[2]):
      return LOW_ARG2;
    case offsetof (seccomp_data, args[3]):
      return LOW_ARG3;
    case offsetof (seccomp_data, args[4]):
      return LOW_ARG4;
    case offsetof (seccomp_data, args[5]):
      return LOW_ARG5;

    case offsetof (seccomp_data, args[0]) + 4:
      return HIGH_ARG0;
    case offsetof (seccomp_data, args[1]) + 4:
      return HIGH_ARG1;
    case offsetof (seccomp_data, args[2]) + 4:
      return HIGH_ARG2;
    case offsetof (seccomp_data, args[3]) + 4:
      return HIGH_ARG3;
    case offsetof (seccomp_data, args[4]) + 4:
      return HIGH_ARG4;
    case offsetof (seccomp_data, args[5]) + 4:
      return HIGH_ARG5;

    default:
      return NULL;
    }
}

uint32_t
STR2ABS (char *str)
{
  if (STARTWITH (str, SYSCALL_NR))
    return offsetof (seccomp_data, nr);
  else if (STARTWITH (str, ARCHITECTURE))
    return offsetof (seccomp_data, arch);

  else if (STARTWITH (str, LOW_PC))
    return offsetof (seccomp_data, instruction_pointer);
  else if (STARTWITH (str, HIGH_PC))
    return offsetof (seccomp_data, instruction_pointer) + 4;

  else if (STARTWITH (str, LOW_ARG0))
    return offsetof (seccomp_data, args[0]);
  else if (STARTWITH (str, LOW_ARG1))
    return offsetof (seccomp_data, args[1]);
  else if (STARTWITH (str, LOW_ARG2))
    return offsetof (seccomp_data, args[2]);
  else if (STARTWITH (str, LOW_ARG3))
    return offsetof (seccomp_data, args[3]);
  else if (STARTWITH (str, LOW_ARG4))
    return offsetof (seccomp_data, args[4]);
  else if (STARTWITH (str, LOW_ARG5))
    return offsetof (seccomp_data, args[5]);

  else if (STARTWITH (str, HIGH_ARG0))
    return offsetof (seccomp_data, args[0]) + 4;
  else if (STARTWITH (str, HIGH_ARG1))
    return offsetof (seccomp_data, args[1]) + 4;
  else if (STARTWITH (str, HIGH_ARG2))
    return offsetof (seccomp_data, args[2]) + 4;
  else if (STARTWITH (str, HIGH_ARG3))
    return offsetof (seccomp_data, args[3]) + 4;
  else if (STARTWITH (str, HIGH_ARG4))
    return offsetof (seccomp_data, args[4]) + 4;
  else if (STARTWITH (str, HIGH_ARG5))
    return offsetof (seccomp_data, args[5]) + 4;
  else
    return -1;
}

char *
RETVAL2STR (uint32_t retval)
{
  switch (retval & ~0xffff)
    {
    case SCMP_ACT_KILL:
      return RED ("KILL");
    case SCMP_ACT_ALLOW:
      return GREEN ("ALLOW");
    case SCMP_ACT_KILL_PROCESS:
      return RED ("KILL_PROCESS");
    case SCMP_ACT_TRAP:
      return YELLOW ("TRAP");
    case SCMP_ACT_NOTIFY:
      return YELLOW ("NOTIFY");
    case SCMP_ACT_LOG:
      return YELLOW ("LOG");
    case SCMP_ACT_ERRNO (0):
      return RED ("ERRNO");
    case SCMP_ACT_TRACE (0):
      return YELLOW ("TRACE");
    default:
      return NULL;
    }
}

int32_t
STR2RETVAL (char *str)
{
  if (strstr (str, "KILL"))
    return SCMP_ACT_KILL;
  else if (strstr (str, "ALLOW"))
    return SCMP_ACT_ALLOW;
  else if (strstr (str, "KILL_PROCESS"))
    return SCMP_ACT_KILL_PROCESS;
  else if (strstr (str, "TRAP"))
    return SCMP_ACT_TRAP;
  else if (strstr (str, "NOTIFY"))
    return SCMP_ACT_NOTIFY;
  else if (strstr (str, "LOG"))
    return SCMP_ACT_LOG;
  else if (strstr (str, "ERRNO"))
    return SCMP_ACT_ERRNO (0);
  else if (strstr (str, "TRACE"))
    return SCMP_ACT_TRACE (0);
  else
    return -1;
}

int32_t
STR2REG (char *str)
{
  if (STARTWITH (str, "$A"))
    return offsetof (reg_mem, A);
  else if (STARTWITH (str, "$X"))
    return offsetof (reg_mem, X);
  else if (!STARTWITH (str, "$mem["))
    return -1;

  char *idx_str = str + strlen ("$mem[");
  char *end = NULL;
  uint32_t idx = strtol (idx_str, &end, 0);
  if (*end != ']' || idx >= BPF_MEMWORDS)
    return -1;

  return offsetof (reg_mem, mem[0]) + idx * sizeof (uint32_t);
}

char *
REG2STR (uint32_t offset)
{
  switch (offset)
    {
    case offsetof (reg_mem, A):
      return "$A";
    case offsetof (reg_mem, X):
      return "$X";
    case offsetof (reg_mem, mem[0x0]):
      return "$mem[0x0]";
    case offsetof (reg_mem, mem[0x1]):
      return "$mem[0x1]";
    case offsetof (reg_mem, mem[0x2]):
      return "$mem[0x2]";
    case offsetof (reg_mem, mem[0x3]):
      return "$mem[0x3]";
    case offsetof (reg_mem, mem[0x4]):
      return "$mem[0x4]";
    case offsetof (reg_mem, mem[0x5]):
      return "$mem[0x5]";
    case offsetof (reg_mem, mem[0x6]):
      return "$mem[0x6]";
    case offsetof (reg_mem, mem[0x7]):
      return "$mem[0x7]";
    case offsetof (reg_mem, mem[0x8]):
      return "$mem[0x8]";
    case offsetof (reg_mem, mem[0x9]):
      return "$mem[0x9]";
    case offsetof (reg_mem, mem[0xa]):
      return "$mem[0xa]";
    case offsetof (reg_mem, mem[0xb]):
      return "$mem[0xb]";
    case offsetof (reg_mem, mem[0xc]):
      return "$mem[0xc]";
    case offsetof (reg_mem, mem[0xd]):
      return "$mem[0xd]";
    case offsetof (reg_mem, mem[0xe]):
      return "$mem[0xe]";
    case offsetof (reg_mem, mem[0xf]):
      return "$mem[0xf]";
    default:
      return NULL;
    }
}
