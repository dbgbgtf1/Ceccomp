# Ceccomp

A tool to analyze seccomp filters like `seccomp-tools`, written in C

# Doc

[English Version](docs/ceccomp.adoc) | [中文文档](docs/ceccomp-cn.adoc)

# Install

- Arch Linux users:

Install via AUR, build `ceccomp` package ⇒ [![AUR package](https://repology.org/badge/version-for-repo/aur/ceccomp.svg)](https://repology.org/project/ceccomp/versions)

- Stable installation:

Clone the whole repo, then run `./configure`.

```sh
git clone https://github.com/dbgbgtf1/Ceccomp.git
cd Ceccomp
./configure
./configure # run this when Makefile is not generated
make DEBUG=1
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

<img width="960" height="681" alt="image" src="https://github.com/user-attachments/assets/e35a1b6f-f3e0-436e-b022-6355b55fd9d7" />

# I need You

Any Issue or Pr are welcome!

# License

Copyright (C) 2025-present, ceccomp contributors, distributed under GNU General Public License v3.0
