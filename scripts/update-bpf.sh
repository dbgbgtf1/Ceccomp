#!/bin/bash

override_bpf()
{
    ./build/ceccomp asm -c always -f raw $1 > $2 2>&1
}

# for txt in test/text/*; do
#     bpf=${txt/text/bpf}
#     bpf=${bpf}.bpf
#     override_bpf $txt $bpf
# done

override_text()
{
    ./build/ceccomp disasm -c always $1 > $2 2>&1
}

for bpf in test/bpf/*; do
    txt=${bpf%.bpf}
    txt=${txt/bpf/text}
    override_text $bpf $txt
done

override_emu()
{
    ./build/ceccomp emu -c always $1 $2 1 2 3 4 5 6 > $3 2>&1
}

for text in test/text/*; do
    emu_result=${text/text/emu_result}
    override_emu $text open $emu_result.open
    override_emu $text pipe $emu_result.pipe
    override_emu $text accept $emu_result.accept
done
