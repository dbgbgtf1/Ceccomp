#define ASM_HINT "ceccomp asm\t[ --arch= ] [ file ] [ --fmt= ]"

#define DISASM_HINT "ceccomp disasm\t[ --arch= ] [ file ]"

#define EMU_HINT                                                              \
  "ceccomp emu\t[ --arch= ] [ file ] [ --quiet ] syscall_nr [ args[0-5] ip ]"

#define PROBE_HINT "ceccomp probe\t[ --arch= ] PROGRAM [ program-args ]"

#define TRACE_HINT                                                            \
  "ceccomp trace\t[ --output= ] PROGRAM [ program-args ]\n"                   \
  "ceccomp trace\t[ --arch= ] --pid="

#define OPTION_HINT                                                           \
  "Options:\n" OPTION_ARCH_HINT OPTION_FMT_HINT OPTION_PID_HINT               \
      OPTION_OUTPUT_HINT OPTION_QUIET_HINT OPTION_ARG_IP_HINT                 \
          OPTION_FILE_HINT

#define OPTION_ARCH_HINT                                                      \
  "-a, --arch=(x86_64|aarch64|...)  to resolve syscall_nr, default as "       \
  "your arch\n"
#define OPTION_FMT_HINT                                                       \
  "-f, --fmt=(hexline|hexfmt|raw)   output format, default as hexline\n"
#define OPTION_PID_HINT                                                       \
  "-p, --pid=system process pid     trace the bpftext of the pid\n"
#define OPTION_OUTPUT_HINT                                                    \
  "-o, --output=file                to avoid ceccomp output mixed with "      \
  "program output, default as stderr\n"
#define OPTION_QUIET_HINT                                                     \
  "-q, --quiet                      print only emulate result\n"
#define OPTION_ARG_IP_HINT                                                    \
  "args[0-5] ip                     args and ip(instruction pointer) used "   \
  "for emulation, default as zero\n"
#define OPTION_FILE_HINT                                                      \
  "file                             file to asm or disasm or emu, default "   \
  "as stdin\n"

#define HELP_HINT "ceccomp help"
#define VERSION "ceccomp version"
