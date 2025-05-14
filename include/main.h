#ifndef MAIN
#define MAIN

// clang-format off
#include <stdint.h>
#include <sys/ptrace.h>
#include <linux/filter.h>
#include <linux/ptrace.h>
#include <linux/seccomp.h>
#include <string.h>
#include <sys/user.h>
// clang-format on

#define ASM_HINT "ceccomp asm [ --arch= ] [ --fmt= ] bpftext"
#define DISASM_HINT "ceccomp disasm [ --arch= ] bpftext"
#define EMU_HINT                                                              \
  "ceccomp emu [ --arch= ] [ --quiet ] bpftext syscall_nr [ args[0-5] ip ]"
#define TRACE_HINT                                                            \
  "ceccomp trace [ PROGRAM [ program-args ] ] | [ [ --arch= ] --pid= ]"
#define PROBE_HINT "ceccomp probe [ --arch= ] PROGRAM [ program-args ]"

#define OPTION_HINT                                                           \
  "Options:\n"                                                                \
  "\t--arch=(i386|x86_64|aarch64|arm|...) default as your arch\n"             \
  "\t--fmt=(hexline|hexfmt|raw)           default as hexline\n"               \
  "\t--quiet                              only print return val\n"            \
  "\t--pid=system process id              print the bpftext of pid\n"         \
  "\targs[0-5]                            default as 0\n"                     \
  "\tip                                   instruction pointer, default as 0"
#define HELP_HINT "ceccomp help"
#define VERSION "ceccomp version"

typedef struct ptrace_syscall_info syscall_info;
typedef struct sock_fprog fprog;
typedef struct sock_filter filter;
typedef struct seccomp_data seccomp_data;
typedef struct user_regs_struct regs;

#define STRAFTER(str, token)                                                  \
  (strstr (str, token) ? strstr (str, token) + strlen (token) : NULL)

#define STARTWITH(str, token) (!strncmp (str, token, strlen (token)))

#endif
