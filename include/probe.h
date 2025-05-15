#ifndef PROBE
#define PROBE

#define ARRAY_SIZE(arr) sizeof (arr) / sizeof (arr[0])
#define CMD_LEN 0x100

extern void probe (int argc, char *argv[]);

#endif
