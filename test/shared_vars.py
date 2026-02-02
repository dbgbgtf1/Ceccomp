from pathlib import Path
import subprocess
import os
from pytest import skip
from types import SimpleNamespace

PROJ_DIR = Path(__file__).parent.parent
TEST_DIR = PROJ_DIR / 'test'
TXT_DIR = TEST_DIR / 'text'
BPF_DIR = TEST_DIR / 'bpf'
EMU_DIR = TEST_DIR / 'emu_result'
BE_DIR  = TEST_DIR / 'big_endian_cases'
CECCOMP = str(PROJ_DIR / 'build' / 'ceccomp')
FILENAMES = sorted([p.stem for p in TXT_DIR.iterdir()])

COMMON_OPTS = ['-c', 'always', '-a', 'x86_64']

def run_process(
    argv: list[str], is_binary: bool=False, extra_fd: int | None=None,
) -> tuple[int, str | bytes, str | bytes]:
    if extra_fd is None:
        result = subprocess.run(argv, timeout=3, capture_output=True,
                                text=not is_binary)
    else:
        result = subprocess.run(argv, timeout=3, capture_output=True,
                                text=not is_binary, pass_fds=(extra_fd, ))
    return result.returncode, result.stdout, result.stderr

_, _verstr, _ = run_process(['pkg-config', '--modversion', 'libseccomp'], False)
SKIP_CHROMIUM = tuple(_verstr.split('.')) < ('2', '5', '6')
SKIP_REASON = 'libseccomp too old (<2.5.6)'
def maybe_skip(filename: str):
    if SKIP_CHROMIUM and filename == 'chromium':
        skip(SKIP_REASON)

def filter2text(filters: bytes) -> str:
    length = len(filters) # leftover (less than 8 bytes) will be discarded
    return '\n'.join(filters[i:i + 8].hex(' ') for i in range(0, length, 8))

os.environ['LC_ALL'] = 'C'
