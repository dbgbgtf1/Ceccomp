#!/bin/bash

diff <(./build/ceccomp disasm ./test/fail_case2/filter > ./test/fail_case2/result 2>&1) ./test/fail_case2/result

if [ $? -eq 0 ]; then
    echo "fail_case2 passed"
else
    echo "fail_case2 failed"
fi
