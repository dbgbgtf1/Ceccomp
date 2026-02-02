import pytest
from shared_vars import *

@pytest.mark.parametrize('filename', FILENAMES)
def test_asm(filename: str, errns: SimpleNamespace):
    maybe_skip(filename)
    input_file = TXT_DIR / filename
    expect_file = BPF_DIR / f'{filename}.bpf'
    _, stdout, stderr = run_process(
        [CECCOMP, 'asm', *COMMON_OPTS, '-f', 'raw', str(input_file)], True,
    )
    errns.stderr = stderr.decode()

    with expect_file.open('rb') as expect:
        assert filter2text(stdout) == filter2text(expect.read())

def test_s390x_asm(errns: SimpleNamespace):
    input_file = BE_DIR / 's390x.text'
    expect_file = BE_DIR / 's390x.hexfmt'
    _, stdout, stderr = run_process(
        [CECCOMP, 'asm', '-f', 'hexfmt', str(input_file), '-a', 's390x'], False,
    )
    errns.stderr = stderr

    with expect_file.open() as expect:
        assert stdout == expect.read()
