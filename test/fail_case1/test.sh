#!/bin/bash

gcc -m32 ./test/fail_case1/test_prog.c -o ./test/fail_case1/test_prog -z now -z noexecstack -fpie -fstack-protector -Wall -Wextra -lseccomp -g3 -O0

diff <(setsid ./build/ceccomp trace -o /dev/stdout 2>/dev/null -c always ./test/fail_case1/test_prog || true) ./test/fail_case1/result

if [ $? -eq 0 ]; then
    echo "fail_case1 passed"
else
    echo "fail_case1 failed"
fi
