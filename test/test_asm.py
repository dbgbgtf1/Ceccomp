import pytest
from shared_vars import *

@pytest.mark.parametrize('filename', FILENAMES)
def test_asm(filename: str):
    maybe_skip(filename)
    input_file = TXT_DIR / filename
    expect_file = BPF_DIR / f'{filename}.bpf'
    _, stdout, stderr = run_process(
        [CECCOMP, 'asm', *COMMON_OPTS, '-f', 'raw', str(input_file)], True,
    )
    with expect_file.open('rb') as expect:
        assert filter2text(stdout) == filter2text(expect.read())
    assert not stderr
