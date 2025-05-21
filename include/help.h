#define ASM_HINT "ceccomp asm     [ -a ARCH ] [ -f FMT ] [ text ]"

#define DISASM_HINT "ceccomp disasm  [ -a ARCH ] [ raw ]"

#define EMU_HINT                                                              \
  "ceccomp emu     [ -a ARCH ] [ -q ] [ text ] syscall_nr [ args[0-5] ip ]"

#define PROBE_HINT                                                            \
  "ceccomp probe   [ -a ARCH ] [ -o FILE ] PROGRAM [ program-args ]"

#define TRACE_HINT                                                            \
  "ceccomp trace   [ -a ARCH ] [ -o FILE ] -p PID\n"                          \
  "                [ -o FILE ] PROGRAM [ program-args ]"

#define OPTION_HINT                                                           \
  "Options:\n" OPTION_ARCH_HINT OPTION_FMT_HINT OPTION_PID_HINT               \
      OPTION_OUTPUT_HINT OPTION_QUIET_HINT ARG_SYSCALL_NR_HINT OPTION_ARG_IP_HINT            \
          OPTION_FILE_HINT

#define OPTION_ARCH_HINT                                                      \
  "-a, --arch (x86_64|aarch64|...)  Which architecture to resolve syscall_nr, default as "       \
  "your arch\n"
#define OPTION_FMT_HINT                                                       \
  "-f, --fmt (hexline|hexfmt|raw)   Output format, default as hexline\n"
#define OPTION_PID_HINT                                                       \
  "-p, --pid system_process_id      Extract bpf filters from process and print " \
  "with bpf text form; CAP_SYS_ADMIN is needed to work\n"
#define OPTION_OUTPUT_HINT                                                    \
  "-o, --output file                Print to file to avoid mixing ceccomp output and "      \
  "tracee program output, default as stderr\n"
#define OPTION_QUIET_HINT                                                     \
  "-q, --quiet                      Print emulate result only\n"
#define ARG_SYSCALL_NR_HINT \
  "syscall_nr                       System call number or name (e.g. 0|read)\n"
#define OPTION_ARG_IP_HINT                                                    \
  "args[0-5], ip                    args and ip (instruction pointer) used "   \
  "for emulation, default as 0\n"
#define OPTION_FILE_HINT                                                      \
  "raw, text                        File with BPF RAW or BPF TEXT, see docs for detail, default "   \
  "as stdin\n"

#define HELP_HINT "ceccomp help"
#define VERSION "ceccomp version"
