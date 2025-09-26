# Ceccomp

A tool to analyze seccomp filters like `seccomp-tools`, written in C

# Doc

[English Version](docs/ceccomp.adoc) | [中文文档](docs/ceccomp-cn.adoc)

# Install

- Arch Linux users:

    Install via AUR, build `ceccomp` package ⇒ [![AUR package](https://repology.org/badge/version-for-repo/aur/ceccomp.svg)](https://repology.org/project/ceccomp/versions)

    Or install via `archlinuxcn` repo if you have it set in you `pacman.conf`.

- Stable installation:

    Clone the whole repo, then run `./configure`. Add `--without-doc` flag if you don't have `asciidoctor`,
    and add `--without-i18n` flag if you don't have `gettext` package.

```sh
git clone https://github.com/dbgbgtf1/Ceccomp.git
cd Ceccomp
./configure
./configure # run this again if Makefile is not generated
make
make install # install at /usr/bin
```

- Testing installation:

    Clone the whole repo, and then run `./configure --devmode`.

```sh
git clone https://github.com/dbgbgtf1/Ceccomp.git
cd Ceccomp
./configure --devmode
make DEBUG=2
```

# CheatSheet

<img width="1185" height="649" alt="image" src="https://github.com/user-attachments/assets/7868a8ed-e6a9-42fa-a2f1-5955be358013" />

# I need You

Any Issue or Pr are welcome!

# Credits

- [seccomp-tools](https://github.com/david942j/seccomp-tools): The tool in Ruby inspires us to write ceccomp
- [Bootswatch](https://bootswatch.com/slate/): Provides awesome css for html doc under MIT

# License

Copyright (C) 2025-present, ceccomp contributors, distributed under GNU General Public License v3.0
