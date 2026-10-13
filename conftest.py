"""Shared pytest wiring for all phases.

* `client` fixture: one BDClient per session.
* Sequential phases: modules marked `sequential` stop at the first failing
  step - later steps are skipped ("Phase failed: stop, notify team").
* Every test's API calls are attached to the HTML report (utils/reporter).
"""
import pytest

from config import settings as _settings
from utils import reporter
from utils.api_client import BDClient


@pytest.fixture(scope="session")
def client():
    return BDClient()


@pytest.fixture(scope="session")
def settings():
    return _settings


def pytest_configure(config):
    config.addinivalue_line("markers", "sequential: steps depend on each other; abort the module on first failure")


@pytest.fixture(autouse=True)
def _sequential_guard(request):
    reporter.drain()                       # drop calls recorded by fixtures
    if request.node.get_closest_marker("sequential"):
        failed = request.module.__dict__.get("_phase_failed")
        if failed:
            pytest.skip(f"aborted: {failed} failed earlier in this phase")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if call.when == "call":
        report.extras = list(getattr(report, "extras", [])) + reporter.to_extras(reporter.drain())
        if report.failed and item.get_closest_marker("sequential"):
            item.module.__dict__["_phase_failed"] = item.name
