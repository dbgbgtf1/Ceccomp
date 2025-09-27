#!/bin/bash

override_text()
{
    ./build/ceccomp disasm -c always $1 > $2
}

for bpf in test/bpf/*.bpf; do
    text=${bpf%.bpf}
    text=${text/bpf/text}
    override_text $bpf $text
done

override_emu()
{
    ./build/ceccomp emu -c always $1 $2 1 2 3 4 5 6 > $3
}

for text in test/text/*; do
    emu_result=${text/text/emu_result}
    override_emu $text open $emu_result.open
    override_emu $text pipe $emu_result.pipe
    override_emu $text accept $emu_result.accept
done

