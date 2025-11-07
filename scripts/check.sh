#!/bin/bash
export LC_ALL=C

# skip chromium if libseccomp lower than 2.5.6
EXPECT_VER=2.5.6
SKIP_CHROMIUM=""
if [ $(echo "$(pkg-config --modversion libseccomp)\n$EXPECT_VER" | sort | head -n1) != "$EXPECT_VER" ]; then
    SKIP_CHROMIUM=1
fi

check_pass ()
{
    if [ $1 -eq 0 ]; then
        echo "[+] $filename passed"
    else
        echo "[x] $filename failed, cat diff_result for details"
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
    if [ -n "$SKIP_CHROMIUM" ] && [ "$filename" == "chromium" ]; then
        echo "[-] libseccomp too old, skip $filename"
        continue
    fi
    diff <(./build/ceccomp disasm $file --color always -a x86_64) ./test/text/$filename > ./build/diff_result
    check_pass $?
  fi
done
echo ""

echo "=====asm test====="
echo ""

files=(./test/text/*)

for file in "${files[@]}"; do
  if [ -f "$file" ]; then
    filename=$(basename "$file")
    if [ -n "$SKIP_CHROMIUM" ] && [ "$filename" == "chromium" ]; then
        echo "[-] libseccomp too old, skip $filename"
        continue
    fi
    diff <(./build/ceccomp asm $file --fmt raw -a x86_64) test/bpf/$filename.bpf > ./build/diff_result
    check_pass $?
  fi
done

echo ""
echo "=====emu test====="
echo ""

for file in "${files[@]}"; do
  if [ -f "$file" ]; then
    filename=$(basename "$file")
    if [ -n "$SKIP_CHROMIUM" ] && [ "$filename" == "chromium" ]; then
        echo "[-] libseccomp too old, skip $filename"
        continue
    fi
    diff <(./build/ceccomp emu -c always -a x86_64 $file open 1 2 3 4 5 6) ./test/emu_result/$filename.open > ./build/diff_result
    check_pass $?
    diff <(./build/ceccomp emu -c always -a x86_64 $file pipe 1 2 3 4 5 6) ./test/emu_result/$filename.pipe > ./build/diff_result
    check_pass $?
    diff <(./build/ceccomp emu -c always -a x86_64 $file accept 1 2 3 4 5 6) ./test/emu_result/$filename.accept > ./build/diff_result
    check_pass $?
  fi
done

echo ""
echo "=====error test====="
echo ""

files=(./test/errors/*.bpf)

for file in "${files[@]}"; do
  if [ -f "$file" ]; then
    filename=$(basename "$file")
    diff <(./build/ceccomp disasm -c always -a x86_64 $file 2>&1) ./test/errors/$filename.err > ./build/diff_result
    check_pass $?
  fi
done

echo ""
echo "=====dynamic test====="
echo ""

make test

filename="trace test"
timeout 0.2 ./build/ceccomp trace -o ./build/dyn_result -c always ./build/test &>/dev/null
diff ./build/dyn_result ./test/trace.log > ./build/diff_result
check_pass $?

filename="probe test"
./build/ceccomp probe -o ./build/dyn_result -c always ./build/test &>/dev/null
diff ./build/dyn_result ./test/probe.log > ./build/diff_result
check_pass $?

if [ "z$(pgrep -f '^./build/test$')z" != "zz" ]; then
  echo "[x] ptrace jail escaped"
  pkill -f "^./build/test$" -9
  exit 1
else
  echo "[+] ptrace jail works"
fi
