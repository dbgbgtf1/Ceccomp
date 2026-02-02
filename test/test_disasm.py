import pytest
from shared_vars import *

@pytest.mark.parametrize('filename', FILENAMES)
def test_disasm(filename: str):
    maybe_skip(filename)
    input_file = BPF_DIR / f'{filename}.bpf'
    expect_file = TXT_DIR / filename
    _, stdout, stderr = run_process(
        [CECCOMP, 'disasm', *COMMON_OPTS, str(input_file)], False,
    )
    with expect_file.open('r') as expect:
        assert stdout == expect.read()
    assert not stderr

def test_s390x_disasm():
    input_file = BE_DIR / 's390x.bpf'
    expect_file = BE_DIR / 's390x.disasm'
    _, stdout, stderr = run_process(
        [CECCOMP, 'disasm', str(input_file), '-a', 's390x'], False,
    )
    with expect_file.open() as expect:
        assert stdout == expect.read()
    assert not stderr
