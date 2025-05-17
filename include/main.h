#ifndef MAIN
#define MAIN

// clang-format off
#include <sys/ptrace.h>
#include <linux/filter.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <sys/types.h>
#include <sys/user.h>
// clang-format on

#define CECCOMP_VERSION "ceccomp 1.6"

#define ASM_HINT "ceccomp asm\t[ --arch= ] [ --fmt= ] bpftext"
#define DISASM_HINT "ceccomp disasm\t[ --arch= ] bpftext"
#define EMU_HINT                                                              \
  "ceccomp emu\t[ --arch= ] [ --quiet ] bpftext syscall_nr [ args[0-5] ip ]"
#define PROBE_HINT "ceccomp probe\t[ --arch= ] PROGRAM [ program-args ]"
#define TRACE_HINT                                                            \
  "ceccomp trace\t[ --output= ] PROGRAM [ program-args ]\n"                   \
  "ceccomp trace\t[ --arch= ] --pid="

#define OPTION_HINT                                                           \
  "Options:\n"                                                                \
  "\t-a,--arch=(x86_64|aarch64|...)   default as your arch\n"                 \
  "\t-f,--fmt=(hexline|hexfmt|raw)    default as hexline\n"                   \
  "\t-p,--pid=system process id       print the bpftext of pid\n"             \
  "\t-o,--output=file                 bpftext output default as stderr\n"     \
  "\targs[0-5] ip                  args and ip(instruction "                  \
  "pointer)default as 0\n"                                                    \
  "\t-q,--quiet                       only print return val\n"

#define HELP_HINT "ceccomp help"
#define VERSION "ceccomp version"

typedef struct sock_fprog fprog;
typedef struct sock_filter filter;
typedef struct seccomp_data seccomp_data;

#define STRAFTER(str, token)                                                  \
  (strstr (str, token) ? strstr (str, token) + strlen (token) : NULL)

#define STARTWITH(str, token) (!strncmp (str, token, strlen (token)))

#endif
