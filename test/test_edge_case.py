import pytest
from shared_vars import *

def test_asm_large_file():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '/dev/zero'],
    )
    assert stderr == '[ERROR]: The input file is greater than 4 MiB!\n'

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
        [CECCOMP, 'asm', '-'], stdin='\n' * 0x4001,
    )
    assert stderr == "[ERROR]: Found more than 16384 lines of text, perhaps it's not for ceccomp?\n"

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
        [CECCOMP, 'asm', '-'], stdin='return ALLOW\n\n' * 4096,
    )
    errns.stderr = stderr
    assert exit_code == 0

def test_asm_4097_statements():
    _, _, stderr = run_process(
        [CECCOMP, 'asm', '-'], stdin='return ALLOW\n' * 4097,
    )
    assert stderr == '[ERROR]: Input file has more than 4096 statements!\n'

def test_disasm_large_file():
    _, _, stderr = run_process(
        [CECCOMP, 'disasm', '/dev/zero'],
    )
    assert stderr == '[ERROR]: The input is larger than 4096 filters! Perhaps inputting a wrong file?\n'

def extract_stdin_stdout(blob: str) -> tuple[str, str]:
    in_idx = blob.find('STDIN')
    out_idx = blob.find('STDOUT')
    assert in_idx != -1 and out_idx != -1
    stdin = blob[in_idx + 6 : out_idx]
    stdout = blob[out_idx + 7:]
    return stdin, stdout

def test_asm_comparators(errns: SimpleNamespace):
    chunk_file = ERR_CASE_DIR / 'e01-asm-comparators'
    with chunk_file.open() as f:
        blob = f.read()
    stdin, stdout = extract_stdin_stdout(blob)

    _, real_out, stderr = run_process(
        [CECCOMP, 'asm', '-', '-a', 'x86_64', '-f', 'hexfmt'], stdin=stdin,
    )
    errns.stderr = stderr
    assert real_out == stdout

def test_disasm_comparators(errns: SimpleNamespace):
    chunk_file = ERR_CASE_DIR / 'e02-disasm-comparators'
    with chunk_file.open() as f:
        blob = f.read()
    stdin, stdout = extract_stdin_stdout(blob)

    stdin = bytes.fromhex(stdin)
    _, real_out, stderr = run_process(
        [CECCOMP, 'disasm', '-', '-a', 'x86_64'], stdin=stdin, is_binary=True,
    )
    errns.stderr = stderr
    assert real_out.decode() == stdout

def test_asm_stx(errns: SimpleNamespace):
    chunk_file = ERR_CASE_DIR / 'e03-asm-stx'
    with chunk_file.open() as f:
        blob = f.read()
    stdin, stdout = extract_stdin_stdout(blob)

    _, real_out, stderr = run_process(
        [CECCOMP, 'asm', '-', '-a', 'x86_64', '-f', 'hexfmt'], stdin=stdin,
    )
    errns.stderr = stderr
    assert real_out == stdout

def test_emu_mem_idx(errns: SimpleNamespace):
    chunk_file = ERR_CASE_DIR / 'e04-mem-idx-access'
    with chunk_file.open() as f:
        blob = f.read()
    stdin, stdout = extract_stdin_stdout(blob)

    _, real_out, stderr = run_process(
        [CECCOMP, 'emu', '-', '-a', 'x86_64', '1'], stdin=stdin,
    )
    errns.stderr = stderr
    assert real_out == stdout

def test_disasm_mem_spread(errns: SimpleNamespace):
    chunk_file = ERR_CASE_DIR / 'e05-mem-idx-spread'
    with chunk_file.open() as f:
        blob = f.read()
    stdin, stdout = extract_stdin_stdout(blob)

    stdin = bytes.fromhex(stdin)
    _, real_out, stderr = run_process(
        [CECCOMP, 'disasm', '-', '-a', 'x86_64'], stdin=stdin, is_binary=True,
    )
    errns.stderr = stderr
    assert real_out.decode() == stdout
