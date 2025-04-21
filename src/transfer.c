#include "../include/transfer.h"
#include "../include/Main.h"
#include "../include/color.h"
#include <seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

const char *const
ARCH2STR (uint32_t token)
{
  switch (token)
    {
    case SCMP_ARCH_X86:
      return "X86";
    case SCMP_ARCH_X86_64:
      return "X86_64";
    case SCMP_ARCH_X32:
      return "X32";
    case SCMP_ARCH_ARM:
      return "ARM";
    case SCMP_ARCH_AARCH64:
      return "AARCH64";
    case SCMP_ARCH_MIPS:
      return "MIPS";
    case SCMP_ARCH_MIPSEL:
      return "MIPSEL";
    case SCMP_ARCH_MIPS64:
      return "MIPS64";
    case SCMP_ARCH_MIPSEL64:
      return "MIPSEL64";
    case SCMP_ARCH_MIPS64N32:
      return "MIPS64N32";
    case SCMP_ARCH_MIPSEL64N32:
      return "MIPSEL64N32";
    case SCMP_ARCH_PARISC:
      return "PARISC";
    case SCMP_ARCH_PARISC64:
      return "PARISC64";
    case SCMP_ARCH_PPC:
      return "PPC";
    case SCMP_ARCH_PPC64:
      return "PPC64";
    case SCMP_ARCH_PPC64LE:
      return "PPC64LE";
    case SCMP_ARCH_S390:
      return "S390";
    case SCMP_ARCH_S390X:
      return "S390X";
    case SCMP_ARCH_RISCV64:
      return "RISCV64";
    default:
      printf ("unknown or unsupported architecture token: 0x%x", token);
      return NULL;
    }
}

const uint32_t
STR2ARCH (const char *const arch)
{
  if (!strcmp (arch, "X86"))
    return SCMP_ARCH_X86;
  else if (!strcmp (arch, "X86_64"))
    return SCMP_ARCH_X86_64;
  else if (!strcmp (arch, "X32"))
    return SCMP_ARCH_X32;
  else if (!strcmp (arch, "ARM"))
    return SCMP_ARCH_ARM;
  else if (!strcmp (arch, "AARCH64"))
    return SCMP_ARCH_AARCH64;
  else if (!strcmp (arch, "MIPS"))
    return SCMP_ARCH_MIPS;
  else if (!strcmp (arch, "MIPSEL"))
    return SCMP_ARCH_MIPSEL;
  else if (!strcmp (arch, "MIPS64"))
    return SCMP_ARCH_MIPS64;
  else if (!strcmp (arch, "MIPSEL64"))
    return SCMP_ARCH_MIPSEL64;
  else if (!strcmp (arch, "MIPS64N32"))
    return SCMP_ARCH_MIPS64N32;
  else if (!strcmp (arch, "MIPSEL64N32"))
    return SCMP_ARCH_MIPSEL64N32;
  else if (!strcmp (arch, "PARISC"))
    return SCMP_ARCH_PARISC;
  else if (!strcmp (arch, "PARISC64"))
    return SCMP_ARCH_PARISC64;
  else if (!strcmp (arch, "PPC"))
    return SCMP_ARCH_PPC;
  else if (!strcmp (arch, "PPC64"))
    return SCMP_ARCH_PPC64;
  else if (!strcmp (arch, "PPC64LE"))
    return SCMP_ARCH_PPC64LE;
  else if (!strcmp (arch, "S390"))
    return SCMP_ARCH_S390;
  else if (!strcmp (arch, "S390X"))
    return SCMP_ARCH_S390X;
  else if (!strcmp (arch, "RISCV64"))
    return SCMP_ARCH_RISCV64;
  else
    printf ("unknown or unsupported architecture name: %s", arch);
  return 0;
}

const char *const
ABS2STR (const uint32_t offset)
{
  switch (offset)
    {
    case offsetof (seccomp_data, nr):
      return syscall_nr;
    case offsetof (seccomp_data, arch):
      return architecture;
    case offsetof (seccomp_data, instruction_pointer):
      return "low pc";
    case offsetof (seccomp_data, instruction_pointer) + 4:
      return "high pc";
    case offsetof (seccomp_data, args[0]):
      return "low args[0]";
    case offsetof (seccomp_data, args[0]) + 4:
      return "high args[0]";
    case offsetof (seccomp_data, args[1]):
      return "low args[1]";
    case offsetof (seccomp_data, args[1]) + 4:
      return "high args[1]";
    case offsetof (seccomp_data, args[2]):
      return "low args[2]";
    case offsetof (seccomp_data, args[2]) + 4:
      return "high args[2]";
    case offsetof (seccomp_data, args[3]):
      return "low args[3]";
    case offsetof (seccomp_data, args[3]) + 4:
      return "high args[3]";
    case offsetof (seccomp_data, args[4]):
      return "low args[4]";
    case offsetof (seccomp_data, args[4]) + 4:
      return "high args[4]";
    case offsetof (seccomp_data, args[5]):
      return "low args[5]";
    case offsetof (seccomp_data, args[5]) + 4:
      return "high args[5]";
    default:
      printf ("unaligned seccomp_data offset: 0x%x\n", offset);
      return NULL;
    }
}

const char *const
RETVAL2STR (const uint32_t retval)
{
  switch (retval & ~0xffff)
    {
    case SCMP_ACT_KILL:
      return RED("KILL");
    case SCMP_ACT_ALLOW:
      return GREEN("ALLOW");
    case SCMP_ACT_KILL_PROCESS:
      return RED("KILL_PROCESS");
    case SCMP_ACT_TRAP:
      return YELLOW("TRAP");
    case SCMP_ACT_NOTIFY:
      return YELLOW("notify");
    case SCMP_ACT_LOG:
      return YELLOW("LOG");
    case SCMP_ACT_ERRNO (0):
      return RED("ERRNO");
    case SCMP_ACT_TRACE (0):
      return YELLOW("TRACE");
    default:
      printf ("unknown ret value of seccomp: 0x%x\n", retval);
      return NULL;
    }
}
