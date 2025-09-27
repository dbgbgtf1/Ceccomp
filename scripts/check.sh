#!/bin/bash

check_pass ()
{
    if [ $1 -eq 0 ]; then
        echo "$filename passed"
    else
        echo "$filename failed, cat diff_result for details"
        exit 1
    fi
}

echo ""
echo "=====disasm test====="
echo ""

files=(./test/bpf/*)

for file in "${files[@]}"; do
  if [ -f "$file" ]; then
    filename=$(basename -s .bpf "$file")
    diff <(./build/ceccomp disasm $file --color always) ./test/text/$filename > ./build/diff_result
    check_pass $?
  fi
done
echo ""

echo =====disasm test passed=====
echo ""

echo "=====asm test====="
echo ""

files=(./test/text/*)

for file in "${files[@]}"; do
  if [ -f "$file" ]; then
    filename=$(basename "$file")
    diff <(./build/ceccomp asm $file --fmt raw) test/bpf/$filename.bpf > ./build/diff_result
    check_pass $?
  fi
done
echo ""

echo =====asm test passed=====
echo ""

echo =====emu test=====

for file in "${files[@]}"; do
  if [ -f "$file" ]; then
    echo ""
    filename=$(basename "$file")
    diff <(./build/ceccomp emu -c always $file open 1 2 3 4 5 6) ./test/emu_result/$filename.open > ./build/diff_result
    check_pass $?
    diff <(./build/ceccomp emu -c always $file pipe 1 2 3 4 5 6) ./test/emu_result/$filename.pipe > ./build/diff_result
    check_pass $?
    diff <(./build/ceccomp emu -c always $file accept 1 2 3 4 5 6) ./test/emu_result/$filename.accept > ./build/diff_result
    check_pass $?
  fi
done
echo ""

echo =====emu test passed=====
echo ""
