#!/bin/bash
export LC_ALL=C

TOLERANT=""
if [ "$1" == "--tolerant" ]; then
    TOLERANT=1
fi
errors=0
debug_file=./build/debug_msg

# skip chromium if libseccomp lower than 2.5.6
EXPECT_VER=2.5.6
TOO_OLD_MSG="libseccomp too old (<2.5.6)"
SKIP_CHROMIUM=""
if [ $(echo -e "$(pkg-config --modversion libseccomp)\n$EXPECT_VER" | sort | head -n1) != "$EXPECT_VER" ]; then
    SKIP_CHROMIUM=1
fi

skip_test ()
{
    echo "[-] $filename skipped, $1"
}

check_pass ()
{
    if [ $1 -eq 0 ]; then
        echo "[+] $filename passed"
    else
        [ -f $debug_file ] && cat $debug_file
        echo "[x] $filename failed"
        if [ -n "$TOLERANT" ]; then
            ((errors += 1))
        else
            exit 1
        fi
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
        skip_test "$TOO_OLD_MSG"
        continue
    fi
    diff -u <(./build/ceccomp disasm $file --color always -a x86_64) ./test/text/$filename
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
        skip_test "$TOO_OLD_MSG"
        continue
    fi
    diff -u <(./build/ceccomp asm $file --fmt raw -a x86_64) test/bpf/$filename.bpf
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
        skip_test "$TOO_OLD_MSG"
        continue
    fi
    diff -u <(./build/ceccomp emu -c always -a x86_64 $file open 1 2 3 4 5 6) ./test/emu_result/$filename.open
    check_pass $?
    diff -u <(./build/ceccomp emu -c always -a x86_64 $file pipe 1 2 3 4 5 6) ./test/emu_result/$filename.pipe
    check_pass $?
    diff -u <(./build/ceccomp emu -c always -a x86_64 $file accept 1 2 3 4 5 6) ./test/emu_result/$filename.accept
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
    diff -u <(./build/ceccomp disasm -c always -a x86_64 $file 2>&1) ./test/errors/$filename.err
    check_pass $?
  fi
done

echo ""
echo "=====dynamic test====="
echo ""

make test

filename="trace test"
timeout 0.2 ./build/ceccomp trace -o ./build/dyn_result -c always ./build/test &>$debug_file
diff -u ./build/dyn_result ./test/trace.log
check_pass $?

filename="probe test"
./build/ceccomp probe -o ./build/dyn_result -c always ./build/test &>$debug_file
diff -u ./build/dyn_result ./test/probe.log
check_pass $?

if [ "z$(pgrep -f '^./build/test$')z" != "zz" ]; then
  echo "[x] ptrace jail escaped"
  pkill -f "^./build/test$" -9
  exit 1
else
  echo "[+] ptrace jail works"
fi

echo ""
echo "=====summary====="
if [ $errors -eq 0 ]; then
    echo "[+] ALL checks passed!"
else
    echo "[x] $errors check(s) failed!"
    exit 1
fi
