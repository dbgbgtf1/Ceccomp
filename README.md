# Ceccomp

A tool to resolve seccomp just like seccomp-tools, written in c  
All functions are done，yet a lot still need to be tested

## What Ceccomp can do

- [x] dump
- [x] emu
- [x] disasm
- [x] asm

## Doc

> some concept to be clear

Kernel load the seccomp with raw `bpf`  
raw `bpf` might look like this  
![raw_bpf](assets/raw_bpf.png)
```
❯ xxd bpf/twctf-2016-diary.bpf
00000000: 2000 0000 0000 0000 1500 0001 0200 0000   ...............
00000010: 0600 0000 0000 0000 1500 0001 0101 0000  ................
00000020: 0600 0000 0000 0000 1500 0001 3b00 0000  ............;...
00000030: 0600 0000 0000 0000 1500 0001 3800 0000  ............8...
00000040: 0600 0000 0000 0000 1500 0001 3900 0000  ............9...
00000050: 0600 0000 0000 0000 1500 0001 3a00 0000  ............:...
00000060: 0600 0000 0000 0000 1500 0001 5500 0000  ............U...
00000070: 0600 0000 0000 0000 1500 0001 4201 0000  ............B...
00000080: 0600 0000 0000 0000 0600 0000 0000 ff7f  ................
```

After Ceccomp resolve the `bpf`, it can print it to `human readable text`  
Might look like this  
![text.png](assets/text.png)
```
❯ ./Ceccomp disasm X86_64 bpf/DEF-CON-2020-bdooos.bpf
 Line  CODE  JT   JF      K
---------------------------------
 0001: 0x20 0x00 0x00 0x00000004 $A = $arch
 0002: 0x15 0x00 0x10 0xc00000b7 if ($A != AARCH64) goto 0019
 0003: 0x20 0x00 0x00 0x00000000 $A = $syscall_nr
 0004: 0x15 0x0d 0x00 0x0000001d if ($A == shmget) goto 0018
 0005: 0x15 0x0c 0x00 0x0000003f if ($A == uname) goto 0018
 0006: 0x15 0x0b 0x00 0x00000040 if ($A == semget) goto 0018
 0007: 0x15 0x0a 0x00 0x00000049 if ($A == flock) goto 0018
 0008: 0x15 0x09 0x00 0x0000005e if ($A == lchown) goto 0018
 0009: 0x15 0x08 0x00 0x00000062 if ($A == getrusage) goto 0018
 0010: 0x15 0x07 0x00 0x00000084 if ($A == utime) goto 0018
 0011: 0x15 0x06 0x00 0x00000086 if ($A == uselib) goto 0018
 0012: 0x15 0x05 0x00 0x0000008b if ($A == sysfs) goto 0018
 0013: 0x15 0x04 0x00 0x000000ce if ($A == io_setup) goto 0018
 0014: 0x15 0x03 0x00 0x000000cf if ($A == io_destroy) goto 0018
 0015: 0x15 0x02 0x00 0x000000d0 if ($A == io_getevents) goto 0018
 0016: 0x15 0x01 0x00 0x000000d7 if ($A == epoll_wait_old) goto 0018
 0017: 0x06 0x00 0x00 0x80000000 return KILL_PROCESS
 0018: 0x06 0x00 0x00 0x7fff0000 return ALLOW
 0019: 0x06 0x00 0x00 0x00000000 return KILL
---------------------------------
```

I will call the `human readable text` with `text` later  
Note that the Line Code JT JF K are not necessary part of `text`, I just decided to print it

**So be sure to understand what `text` and `bpf` means**

### Dump

#### what dump does

Dump mode can dump program `bpf` out, and then print it out to `text`

> It can be useful when you want to know what seccomp a program loads

#### what dump looks like

![dump](assets/dump.png)
```
❯ ./Ceccomp dump test
 Line  CODE  JT   JF      K
---------------------------------
 0001: 0x20 0x00 0x00 0x00000004 $A = $arch
 0002: 0x15 0x00 0x09 0xc000003e if ($A != X86_64) goto 0012
 0003: 0x20 0x00 0x00 0x00000000 $A = $syscall_nr
 0004: 0x25 0x06 0x00 0xffffffff if ($A > 0xffffffff) goto 0011
 0005: 0x15 0x00 0x06 0x00000000 if ($A != read) goto 0012
 0006: 0x20 0x00 0x00 0x00000010 $A = $low_args[0]
 0007: 0x15 0x04 0x03 0x00000005 if ($A == 0x5) goto 0012, else goto 0011
 0008: 0x20 0x00 0x00 0x00000014 $A = $high_args[0]
 0009: 0x15 0x00 0x02 0x00000002 if ($A != 0x2) goto 0012
 0010: 0x06 0x00 0x00 0x00051111 return ERRNO
 0011: 0x06 0x00 0x00 0x7fff0000 return ALLOW
 0012: 0x06 0x00 0x00 0x80000000 return KILL_PROCESS
---------------------------------
child process status: 159
```

#### dump usages

`Ceccomp dump program [ program-args ]`, add program-args if necessary

Find a program that will load seccomp

### Emulate

#### what emu does

Emulate what will happen if `syscall (nr, args ...)` were called

> It can be useful when you don't want to read `text`

#### what emu looks like

A code block won't show color, so take a look at the picture

![emu](assets/emu.png)

#### emu usages

`Ceccomp emu text arch nr [ argv[0] - argv[5] ] (default as 0)`

`arch` must be specified  
Otherwise the Ceccomp can't transfer something like `write` to its syscallnr

## Disasm

#### what disasm does

Disasm from `bpf` to `text`

> It can be useful when the program don't load seccomp at once

So you can use gdb to get the raw `bpf` manualy, Disasm will do the rest for you

#### what disasm looks like

![disasm](assets/disasm.png)
```
❯ ./Ceccomp disasm X86_64 bpf/DEF-CON-2020-bdooos.bpf
 Line  CODE  JT   JF      K
---------------------------------
 0001: 0x20 0x00 0x00 0x00000004 $A = $arch
 0002: 0x15 0x00 0x10 0xc00000b7 if ($A != AARCH64) goto 0019
 0003: 0x20 0x00 0x00 0x00000000 $A = $syscall_nr
 0004: 0x15 0x0d 0x00 0x0000001d if ($A == shmget) goto 0018
 0005: 0x15 0x0c 0x00 0x0000003f if ($A == uname) goto 0018
 0006: 0x15 0x0b 0x00 0x00000040 if ($A == semget) goto 0018
 0007: 0x15 0x0a 0x00 0x00000049 if ($A == flock) goto 0018
 0008: 0x15 0x09 0x00 0x0000005e if ($A == lchown) goto 0018
 0009: 0x15 0x08 0x00 0x00000062 if ($A == getrusage) goto 0018
 0010: 0x15 0x07 0x00 0x00000084 if ($A == utime) goto 0018
 0011: 0x15 0x06 0x00 0x00000086 if ($A == uselib) goto 0018
 0012: 0x15 0x05 0x00 0x0000008b if ($A == sysfs) goto 0018
 0013: 0x15 0x04 0x00 0x000000ce if ($A == io_setup) goto 0018
 0014: 0x15 0x03 0x00 0x000000cf if ($A == io_destroy) goto 0018
 0015: 0x15 0x02 0x00 0x000000d0 if ($A == io_getevents) goto 0018
 0016: 0x15 0x01 0x00 0x000000d7 if ($A == epoll_wait_old) goto 0018
 0017: 0x06 0x00 0x00 0x80000000 return KILL_PROCESS
 0018: 0x06 0x00 0x00 0x7fff0000 return ALLOW
 0019: 0x06 0x00 0x00 0x00000000 return KILL
---------------------------------
❯ xxd bpf/DEF-CON-2020-bdooos.bpf
00000000: 2000 0000 0400 0000 1500 0010 b700 00c0   ...............
00000010: 2000 0000 0000 0000 1500 0d00 1d00 0000   ...............
00000020: 1500 0c00 3f00 0000 1500 0b00 4000 0000  ....?.......@...
00000030: 1500 0a00 4900 0000 1500 0900 5e00 0000  ....I.......^...
00000040: 1500 0800 6200 0000 1500 0700 8400 0000  ....b...........
00000050: 1500 0600 8600 0000 1500 0500 8b00 0000  ................
00000060: 1500 0400 ce00 0000 1500 0300 cf00 0000  ................
00000070: 1500 0200 d000 0000 1500 0100 d700 0000  ................
00000080: 0600 0000 0000 0080 0600 0000 0000 ff7f  ................
00000090: 0600 0000 0000 0000                      ........
```

#### disasm usages

`Ceccomp disasm arch xxx.bpf`

Just like emu, arch must be specified  
Then just add the `bpf` you want to resolve

## Asm

#### what asm does

Asm the `bpf` from `text`

> It could be useful when you need to write your own seccomp

(but make sure you write the asm in correct way

I might write a simple guide about the basic rules)

#### what asm looks like

It might look too simple  
I designed asm this way, copying `bpf` will be easier

![asm](assets/asm.png)
```
❯ cat result
 $A = $arch
 if ($A != AARCH64) goto 0019
 $A = $syscall_nr
 if ($A == shmget) goto 0018
 if ($A == uname) goto 0018
 if ($A == semget) goto 0018
 if ($A == flock) goto 0018
 if ($A == lchown) goto 0018
 if ($A == getrusage) goto 0018
 if ($A == utime) goto 0018
 if ($A == uselib) goto 0018
 if ($A == sysfs) goto 0018
 if ($A == io_setup) goto 0018
 if ($A == io_destroy) goto 0018
 if ($A == io_getevents) goto 0018
 if ($A == epoll_wait_old) goto 0018
 return KILL_PROCESS
 return ALLOW
 return KILL
❯ ./Ceccomp asm X86_64 result
0020 00 00 00000004
0015 00 10 c00000b7
0020 00 00 00000000
0015 0d 00 0000001d
0015 0c 00 0000003f
0015 0b 00 00000040
0015 0a 00 00000049
0015 09 00 0000005e
0015 08 00 00000062
0015 07 00 00000084
0015 06 00 00000086
0015 05 00 0000008b
0015 04 00 000000ce
0015 03 00 000000cf
0015 02 00 000000d0
0015 01 00 000000d7
0006 00 00 00000000
0006 00 00 7fff0000
0006 00 00 00000000
```

#### asm usages

`Ceccomp asm arch text`

Just like disasm, emu, `arch` must be specified, then add the `text`  
And you can write you own `text`, asm will asm `text` to `bpf`

## Supported architecture
- X86
- X86-64
- X32
- ARM
- AARCH64
- MIPS
- MIPSEL
- MIPSEL64
- MIPSEL64N32
- PARISC
- PARISC64
- PPC
- PPC64
- PPC64LE
- S390
- S390X
- RISCV64
