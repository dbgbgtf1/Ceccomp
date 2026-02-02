from types import SimpleNamespace
import pytest

@pytest.fixture
def errns() -> SimpleNamespace:
    return SimpleNamespace()

# hook pytest report to print stderr
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()

    if report.when == 'call' and report.failed:
        ns = item.funcargs.get('errns')
        if hasattr(ns, 'stderr'):
            report.sections.append(('Process Standard Error', ns.stderr))
