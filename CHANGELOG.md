# CHANGELOG
Items marked with :star: is the major change why we release a new version.
## 3.0 (INCOMING)
* **BREAKING** Remove `-o FILE` for `trace` pid mode
* :star: Add doc system powered by *asciidoc* #2
* :star: Add signal forwarding to `trace` in expected way #5
* :star: Add subcommand description #7
* :star: Add color option, can be set to always, auto, never #10
* Warn invalid seccomp filter instead of refuse directly #4
* Raise errors on corrupted TEXT in `emu`
* Suppress printing function if not debugging
* Set `$?` to 1 when failed to parse args
* Limit truncating file on `-o` flag by checking subcommand
* Update color in `return $A` BPF OP for better visual effect
* Implement assigning `len(struct seccomp_data)` to `A` or `X`
## 2.9
* :star: Fix Makefile compatibility among shells #6
* Add git-hook to remind dev to update version string
* Update color in `return` BPF OP for better visual effect
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
* :star: Add parentheses for `TRAP` as it has `ret_data`, but *libseccomp* doesn't implement it
  seccomp/libseccomp#466
* Add check script
* Fix uninitialized memory access
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
