import pytest
from shared_vars import *

def test_asm_large_file():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '/dev/zero'],
    )
    assert stderr == '[ERROR]: The input file is greater than 1 MiB!\n'

def test_asm_no_lf():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='1' * 0x400,
    )
    assert stderr == "[ERROR]: No line break in source file, perhaps it's not a text file?\n"

def test_asm_long_line():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='\n\n' + '1' * 0x400 + '\n',
    )
    assert stderr == '[ERROR]: Line 3 has more than 384 bytes, perhaps the input is not a text file?\n'

def test_asm_many_lines():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='\n' * 0x2000,
    )
    assert stderr == "[ERROR]: Found more than 4096 lines of text, perhaps it's not for ceccomp?\n"

def test_asm_0_file():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='\n\n\0\n',
    )
    assert stderr == "[ERROR]: Found '\\0' at file offset 2, perhaps it's not a text file?\n"

def test_asm_empty_file():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='# \n',
    )
    assert stderr == '[ERROR]: The input does not contain any valid statement\n'

def test_asm_4096_statements(errns: SimpleNamespace):
    exit_code, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='return ALLOW\n\n' * 1024,
    )
    errns.stderr = stderr
    assert exit_code == 0

def test_asm_4097_statements():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='return ALLOW\n' * 1025,
    )
    assert stderr == '[ERROR]: Input file has more than 1024 statements!\n'

def test_disasm_large_file():
    _, _, stderr = run_process(
        [CECCOMP, 'disasm', '/dev/zero'],
    )
    assert stderr == '[ERROR]: The input is larger than 1024 filters! Perhaps inputting a wrong file?\n'

def test_asm_comparators(errns: SimpleNamespace):
    chunk_file = ERR_CASE_DIR / 'e01-asm-comparators'
    with chunk_file.open() as f:
        blob = f.read()
    in_idx = blob.find('STDIN')
    out_idx = blob.find('STDOUT')
    assert in_idx != -1 and out_idx != -1

    stdin = blob[in_idx + 6 : out_idx]
    _, stdout, stderr = run_process(
        [CECCOMP, 'asm', '-', '-a', 'x86_64', '-f', 'hexfmt'], stdin=stdin,
    )
    errns.stderr = stderr
    assert stdout == blob[out_idx + 7:]

def test_disasm_comparators(errns: SimpleNamespace):
    chunk_file = ERR_CASE_DIR / 'e02-disasm-comparators'
    with chunk_file.open() as f:
        blob = f.read()
    in_idx = blob.find('STDIN')
    out_idx = blob.find('STDOUT')
    assert in_idx != -1 and out_idx != -1

    stdin = bytes.fromhex(blob[in_idx + 6 : out_idx])
    _, stdout, stderr = run_process(
        [CECCOMP, 'disasm', '-', '-a', 'x86_64'], stdin=stdin, is_binary=True,
    )
    errns.stderr = stderr
    assert stdout.decode() == blob[out_idx + 7:]
