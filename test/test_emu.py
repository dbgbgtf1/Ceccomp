import pytest
from shared_vars import *

EMU_TARGETS = []
for filename in FILENAMES:
    EMU_TARGETS.append((filename, 'accept'))
    EMU_TARGETS.append((filename, 'open'))
    EMU_TARGETS.append((filename, 'pipe'))

@pytest.mark.parametrize('filename, suffix', EMU_TARGETS)
def test_emu(filename: str, suffix: str):
    maybe_skip(filename)
    input_file = TXT_DIR / filename
    expect_file = EMU_DIR / f'{filename}.{suffix}'
    emu_args = [suffix, '1', '2', '3', '4', '5', '6']
    _, stdout, stderr = run_process(
        [CECCOMP, 'emu', *COMMON_OPTS, str(input_file), *emu_args], False,
    )
    with expect_file.open('r') as expect:
        assert stdout == expect.read()
    assert not stderr
