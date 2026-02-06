import pytest
from shared_vars import *
from subprocess import PIPE, DEVNULL
import signal
import time
import select

def is_not_cap_sys_admin() -> str | None:
    try:
        with open('/proc/self/status') as f:
            for line in f:
                if line.startswith('CapEff:'):
                    capeff = int(line.split()[1], 16)
                    break
            else:
                return 'Capability can not be found in status'
    except OSError:
        return 'Can not query /proc to know capability'

    if bool(capeff & (1 << 21)): # CAP_SYS_ADMIN = 21
        return None
    return 'Lack of CAP_SYS_ADMIN capability'

TEST = str(PROJ_DIR / 'build' / 'test')
assert run_process(['make', '-C', str(PROJ_DIR), 'test'], False)[0] == 0

def pid_state(pid: int) -> str | None:
    """
    Race condition: perhaps kernel killed process but ceccomp hasn't exit,
    so test is zombie and not being collected. Test this case
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    try:
        with open(f'/proc/{pid}/stat') as f:
            state = f.read().split(' ', 4)[2]
    except:
        return None
    else:
        return None if state == 'Z' else state

def filter_execve_k(text: str) -> str:
    if len(text) != 391:
        return text
    try:
        int(text[174:184], 16)
    except ValueError:
        return text
    return text[:174] + ' MAY VARY ' + text[184:]

# -a x86_64 option in COMMON_OPTS will be ignored in trace/probe

##### TEST CASES #####
def test_probe(errns: SimpleNamespace):
    piper, pipew = os.pipe()
    os.set_inheritable(pipew, True)
    argv = [CECCOMP, 'probe', *COMMON_OPTS, '-o', f'/proc/self/fd/{pipew}', TEST, '1']
    _, stdout, stderr = run_process(argv, False, pipew)
    os.close(pipew)
    errns.stderr = stderr

    expect_file = TEST_DIR / 'dyn_log' / 'probe.log'
    with expect_file.open() as f:
        expect = f.read()
    with os.fdopen(piper) as f:
        assert f.read() == expect

    pid = int(stdout.split('=')[1])
    end = time.time() + 1
    while pid_state(pid) and time.time() < end:
        time.sleep(0.0625)
    assert pid_state(pid) is None


def test_trace(errns: SimpleNamespace):
    piper, pipew = os.pipe()
    os.set_inheritable(pipew, True)
    argv = [CECCOMP, 'trace', *COMMON_OPTS, '-o', f'/proc/self/fd/{pipew}', TEST, '0']
    _, _, stderr = run_process(argv, False, pipew)
    os.close(pipew)
    errns.stderr = stderr

    expect_file = TEST_DIR / 'dyn_log' / 'trace.log'
    with expect_file.open() as f:
        expect = f.read()
    with os.fdopen(piper) as f:
        assert filter_execve_k(f.read()) == filter_execve_k(expect)
    assert 'WARN' in stderr


def test_seize(errns: SimpleNamespace):
    tp = subprocess.Popen([TEST, '2'], stdin=DEVNULL, stdout=PIPE, stderr=DEVNULL, text=True)
    pid = int(tp.stdout.readline().split('=')[1])

    argv = [CECCOMP, 'trace', *COMMON_OPTS, '-p', str(pid), '-s']
    cp = subprocess.Popen(argv, stdin=DEVNULL, stdout=PIPE, stderr=PIPE, text=True)
    pre_line = cp.stderr.readline()

    os.kill(pid, signal.SIGCONT)

    rl, _, _ = select.select([tp.stdout], [], [], 0.5)
    if rl:
        pid = int(rl[0].readline().split('=')[1]) # child pid
    else:
        with open(f'/proc/{tp.pid}/wchan') as f:
            t_kfunc = f.read()
        with open(f'/proc/{cp.pid}/wchan') as f:
            c_kfunc = f.read()
        errns.stderr = f'TEST in {t_kfunc}\nCECCOMP in {c_kfunc}'
        tp.terminate()
        cp.terminate()
        assert False, 'Found signal race condition? Pls report to upstream'

    cp.terminate()
    stdout, stderr = cp.communicate()
    errns.stderr = pre_line + stderr

    pid_exist = True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        pid_exist = False
    else:
        os.kill(pid, signal.SIGCONT)
    assert pid_exist is True

    expect_file = TEST_DIR / 'dyn_log' / 'trace.log'
    with expect_file.open() as f:
        assert filter_execve_k(stdout) == filter_execve_k(f.read())

def test_trace_pid(errns: SimpleNamespace):
    if msg := is_not_cap_sys_admin():
        pytest.skip(msg)

    tp = subprocess.Popen([TEST, '3'], stdin=DEVNULL, stdout=PIPE, stderr=DEVNULL, text=True)
    pid = int(tp.stdout.readline().split('=')[1])

    _, stdout, stderr = run_process(
        [CECCOMP, 'trace', *COMMON_OPTS, '-p', str(pid)],
    )
    errns.stderr = stderr

    os.kill(pid, signal.SIGCONT)

    expect_file = TEST_DIR / 'dyn_log' / 'trace.log'
    with expect_file.open() as f:
        assert filter_execve_k(stdout) == filter_execve_k(f.read())
