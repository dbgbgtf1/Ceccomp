#!/bin/bash

echo "=====disasm test====="
echo ""

files=(./bpf/*)

for file in "${files[@]}"; do
  if [ -f "$file" ]; then
    filename=$(basename -s .bpf "$file")
    ./build/ceccomp disasm $file --color always | diff /dev/stdin ./text/$filename > diff_result > diff_result
    if [ $(echo $?) == 0 ]; then
        echo "$filename passed"
    else
        echo "$filename failed, cat diff_result for details"
        exit 1
    fi
  fi
done
echo ""

echo =====disasm test passed=====
echo ""

echo "=====asm test====="
echo ""

files=(./text/*)

for file in "${files[@]}"; do
  if [ -f "$file" ]; then
    filename=$(basename "$file")
    ./build/ceccomp asm $file --fmt raw | diff /dev/stdin ./bpf/$filename.bpf > diff_result
    if [ $(echo $?) == 0 ]; then
        echo "$filename passed"
    else
        echo "$filename failed, cat diff_result for details"
        exit 1
    fi
  fi
done
echo ""

echo =====asm test passed=====
echo ""
