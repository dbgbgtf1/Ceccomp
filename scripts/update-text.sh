#!/bin/bash

override_text() {
    ./build/ceccomp disasm -c always $1 > $2
}

for bpf in test/bpf/*.bpf; do
    text=${bpf%.bpf}
    text=${text/bpf/text}
    override_text $bpf $text
done
