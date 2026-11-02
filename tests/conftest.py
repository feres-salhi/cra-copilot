"""Shared test setup: the printed command name is fixed to "cra" so older tests do not depend on the machine.
The real derivation is tested in test_cli_name.py (which switches this fixed value off).

Also: a test can NEVER show a real desktop notification. The default notifier is replaced by a fake that only counts."""
import pytest

from src import alerts, cli_name


@pytest.fixture(autouse=True)
def _fixed_command_name():
    cli_name.set_override("cra")
    yield
    cli_name.set_override(None)


class NoRealNotifications:
    def __init__(self):
        self.calls = []

    def __call__(self, title, body):
        self.calls.append((title, body))
        return True


@pytest.fixture(autouse=True)
def _no_real_notifications():
    fake = NoRealNotifications()
    alerts.set_override(fake)
    yield fake
    alerts.set_override(None)
