#include "i18n.h"
#define CECCOMP_USAGE _ ("Usage: ceccomp <subcommand> <args> <options>\n")
#define ASM_HINT "ceccomp asm     [ -c WHEN ] [ -a ARCH ] [ -f FMT ] [ text ]"

#define DISASM_HINT "ceccomp disasm  [ -c WHEN ] [ -a ARCH ] [ raw ]"

#define EMU_HINT                                                              \
  "ceccomp emu     [ -c WHEN ] [ -a ARCH ] [ -q ] text syscall_nr [ "         \
  "args[0-5] ip ]"

#define PROBE_HINT                                                            \
  "ceccomp probe   [ -c WHEN ] [ -a ARCH ] [ -o FILE ] PROGRAM [ "            \
  "program-args ]"

#define TRACE_HINT                                                            \
  "ceccomp trace   [ -c WHEN ] [ -a ARCH ] [ -o FILE ] -p PID\n"              \
  "                [ -c WHEN ] [ -o FILE ] PROGRAM [ program-args ]"

#define HELP_HINT "ceccomp help"
#define VERSION_HINT "ceccomp version"

#define SUBCMD_HINT                                                           \
  _ ("asm      -- Assemble bpf text to raw bytes\n"                           \
     "disasm   -- Disassemble raw bytes to bpf text\n"                        \
     "emu      -- Emulate bpf program with given syscall and bpf text\n"      \
     "help     -- Display ceccomp help information\n"                         \
     "probe    -- Trace the program for the first filter and emulate common " \
     "syscalls\n"                                                             \
     "trace    -- Run program or trace pid, extract bpf filter and then "     \
     "print "                                                                 \
     "to text\n"                                                              \
     "version  -- Display ceccomp version\n")

#define OPTION_HINT                                                           \
  _ ("Options:\n"                                                             \
     "-a, --arch (x86_64|aarch64|...)  Which architecture to resolve "        \
     "syscall_nr, default as your arch\n"                                     \
                                                                              \
     "-f, --fmt (hexline|hexfmt|raw)   Output format, default as hexline\n"   \
                                                                              \
     "-p, --pid system_process_id      Extract bpf filters from process and " \
     "print with bpf text form; CAP_SYS_ADMIN is needed to work\n"            \
                                                                              \
     "-o, --output file                Print to file to avoid mixing "        \
     "ceccomp output and tracee program output, default as stderr\n"          \
                                                                              \
     "-q, --quiet                      Print emulate result only\n"           \
                                                                              \
     "-c, --color                      When to print in color, default as "   \
     "auto\n"                                                                 \
                                                                              \
     "syscall_nr                       System call number or name (e.g. "     \
     "0|read)\n"                                                              \
     "args[0-5], ip                    args and ip (instruction pointer) "    \
     "used for emulation, default as 0\n"                                     \
     "raw, text                        File with BPF RAW or BPF TEXT, see "   \
     "docs for detail, default as stdin\n")
