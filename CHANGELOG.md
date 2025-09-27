# CHANGELOG
Items marked with :star: is the major change why we release a new version.

<!-- When referencing issues and PRs, add #num at the end of line for issues -->
<!-- and !num at the end of line for PRs. If the issue or PR is external, -->
<!-- write user/repo#num or user/repo!num to reference. Then run scripts/complete-url.py -->
<!-- to format raw ref to URL. -->

## 3.2
* **BREAKING** :star: Enhance arch/syscall prediction :link: [#12]
* :star: Add support for Debian build system :link: [#13]
* :star: Improve syntax highlighting
* Hide unused bpf operation in emu :link: [#14]
* Fix `CECCOMP_USAGE` warning as it's a function call
* Add a dark-mode css for html doc
* Sort source object for reproducible build

[#13]: https://github.com/dbgbgtf1/Ceccomp/issues/13
[#12]: https://github.com/dbgbgtf1/Ceccomp/issues/12
[#14]: https://github.com/dbgbgtf1/Ceccomp/issues/14
## 3.1
* **BREAKING** :star: Add support for multiple process tracing :link: [#3]
* :star: Cover all cases of trace pid errors :link: [#11]
* :star: Add support for internationalization/localization :link: [#1]
* :star: Fix `ld` error when compiling on Kali Linux
* Fix potential misuse of `Info` in trace
* Improve log system and related color management
* Fix output file may not be opened correctly
* Add a GitHub action to issue new release easily

[#3]: https://github.com/dbgbgtf1/Ceccomp/issues/3
[#11]: https://github.com/dbgbgtf1/Ceccomp/issues/11
[#1]: https://github.com/dbgbgtf1/Ceccomp/issues/1
## 3.0
* **BREAKING** Remove `-o FILE` for `trace` pid mode
* :star: Add doc system powered by *asciidoc* :link: [#2]
* :star: Add signal forwarding to `trace` in expected way :link: [#5]
* :star: Add subcommand description :link: [#7]
* :star: Add color option, can be set to always, auto, never :link: [#10]
* :star: Add Python-version configure script :link: [#9]
* Warn invalid seccomp filter instead of refuse directly :link: [#4]
* Raise errors on corrupted TEXT in `emu`
* Suppress printing function if not debugging
* Set `$?` to 1 when failed to parse args
* Limit truncating file on `-o` flag by checking subcommand
* Update color in `return $A` BPF OP for better visual effect
* Implement assigning `len(struct seccomp_data)` to `A` or `X`
* Implement uninstall operation and verbose control in Makefile

[#2]: https://github.com/dbgbgtf1/Ceccomp/issues/2
[#5]: https://github.com/dbgbgtf1/Ceccomp/issues/5
[#7]: https://github.com/dbgbgtf1/Ceccomp/issues/7
[#10]: https://github.com/dbgbgtf1/Ceccomp/issues/10
[#4]: https://github.com/dbgbgtf1/Ceccomp/issues/4
[#9]: https://github.com/dbgbgtf1/Ceccomp/issues/9
## 2.9
* :star: Fix Makefile compatibility among shells :link: [#6]
* Add git-hook to remind dev to update version string
* Update color in `return` BPF OP for better visual effect

[#6]: https://github.com/dbgbgtf1/Ceccomp/issues/6
## 2.8
* :star: Improve compatibility among compilers
* :star: Add Kbuild-like build prompt with progress
* Improve logging implementation
## 2.7
* :star: Fix `trace` and `probe` foreground interaction issue
* Refactor method to terminate children
## 2.6
* :star: Fix Makefile link order (should be put in the end of line)
* Suppress compiler warning by `// fall through`
* Applying more checks on `asm`
## 2.5
* :star: Add parentheses for `TRAP` as it has `ret_data`, but *libseccomp* hasn't implement it :link: [seccomp/libseccomp#466]
* Add check script
* Fix uninitialized memory access

[seccomp/libseccomp#466]: https://github.com/seccomp/libseccomp/issues/466
## 2.4
* :star: Port kernel filter check
* Add some logging functions
## 2.3
* Fix `asm` lacking `ALU_NEG` operation
* Fix `asm` hanging if
## 2.2
* Fix `emu` emulates wrong ALU operations
* Better help message
## 2.1
* Remove `CXX` in Makefile, now it's purely in C
* Fix Makefile typo
## 2.0
* :star: Turn to `argp` to parse arguments
* :star: Add `-o` mode to output filters
* :star: Use C to implement `parsefilter`
## 1.5
* :star: New probe mode to test common syscalls instantly
* Adapt completion script to latest code base
## 1.4
* Fix lacking `\n` in trace
## 1.3
* `trace` now accept pid to grab filters
* Zsh completion script is capable of completing pid
## 1.2
* :star: Ready for PKGBUILD to build package
* Fix zsh completion script
## 1.1
* First release version
* Add basic zsh completion script
