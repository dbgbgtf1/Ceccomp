#!/bin/bash

gcc -m32 ./test/fail_case3/test_prog.c -o ./test/fail_case3/test_prog -z now -z noexecstack -fpie -fstack-protector -Wall -Wextra -lseccomp -g3 -O0

diff <(setsid ./build/ceccomp trace -c always -o /dev/stdout 2>/dev/null ./test/fail_case3/test_prog) ./test/fail_case3/result

if [ $? -eq 0 ]; then
    echo "fail_case3 passed"
else
    echo "fail_case3 failed"
fi
