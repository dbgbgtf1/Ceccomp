from sys import stderr
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
        [CECCOMP, 'asm', '-f', 'hexfmt', str(input_file), '-a', 's390x'],
    )
    errns.stderr = stderr

    with expect_file.open() as expect:
        assert stdout == expect.read()

def test_large_file():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '/dev/zero'],
    )
    assert stderr == '[ERROR]: The input file is greater than 1 MiB!\n'

def test_no_lf():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='1' * 0x400,
    )
    assert stderr == "[ERROR]: No line break in source file, perhaps it's not a text file?\n"

def test_long_line():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='\n\n' + '1' * 0x400 + '\n',
    )
    assert stderr == '[ERROR]: Line 3 has more than 384 bytes, perhaps the input is not a text file?\n'

def test_many_lines():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='\n' * 0x2000,
    )
    assert stderr == "[ERROR]: Found more than 4096 lines of text, perhaps it's not for ceccomp?\n"

def test_0_file():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='\n\n\0\n',
    )
    assert stderr == "[ERROR]: Found '\\0' at file offset 2, perhaps it's not a text file?\n"

def test_empty_file():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='# \n',
    )
    assert stderr == '[ERROR]: The input does not contain any valid statement\n'

def test_4096_statements(errns: SimpleNamespace):
    exit_code, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='return ALLOW\n\n' * 1024,
    )
    errns.stderr = stderr
    assert exit_code == 0

def test_4097_statements():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='return ALLOW\n' * 1025,
    )
    assert stderr == '[ERROR]: Input file has more than 1024 statements!\n'

ERROR_IDS = sorted([p.stem[1:] for p in (TEST_DIR / 'errors').glob('a*')])

@pytest.mark.parametrize('errorid', ERROR_IDS)
def test_error_cases(errorid: str):
    chunk_file = TEST_DIR / 'errors' / f'a{errorid}'
    with chunk_file.open() as f:
        blob = f.read()
    in_idx = blob.find('STDIN')
    err_idx = blob.find('STDERR')
    assert in_idx != -1 and err_idx != -1

    stdin = blob[in_idx + 6 : err_idx]
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin=stdin,
    )
    assert stderr == blob[err_idx + 7:]
