import pytest
from shared_vars import *

@pytest.mark.parametrize('filename', FILENAMES)
def test_disasm(filename: str, errns: SimpleNamespace):
    maybe_skip(filename)
    input_file = BPF_DIR / f'{filename}.bpf'
    expect_file = TXT_DIR / filename
    _, stdout, stderr = run_process(
        [CECCOMP, 'disasm', *COMMON_OPTS, str(input_file)],
    )
    errns.stderr = stderr

    with expect_file.open('r') as expect:
        assert stdout == expect.read()

def test_s390x_disasm(errns: SimpleNamespace):
    input_file = BE_DIR / 's390x.bpf'
    expect_file = BE_DIR / 's390x.disasm'
    _, stdout, stderr = run_process(
        [CECCOMP, 'disasm', str(input_file), '-a', 's390x'],
    )
    errns.stderr = stderr

    with expect_file.open() as expect:
        assert stdout == expect.read()

ERROR_IDS = sorted([p.stem[1:] for p in ERR_CASE_DIR.glob('b*')])

@pytest.mark.parametrize('errorid', ERROR_IDS)
def test_error_cases(errorid: str):
    chunk_file = ERR_CASE_DIR / f'b{errorid}'
    with chunk_file.open() as f:
        blob = f.read()
    in_idx = blob.find('STDIN')
    out_idx = blob.find('STDOUT')
    err_idx = blob.find('STDERR')
    assert in_idx != -1 and err_idx != -1

    stdin = bytes.fromhex(blob[in_idx + 6 : err_idx])
    _, stdout, stderr = run_process(
        [CECCOMP, 'disasm', '-', '-a', 'x86_64'], stdin=stdin, is_binary=True,
    )
    if out_idx == -1:
        assert stderr.decode() == blob[err_idx + 7:]
    else:
        assert stderr.decode() == blob[err_idx + 7 : out_idx]
        assert stdout.decode() == blob[out_idx + 7:]
