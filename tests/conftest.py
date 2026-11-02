"""Shared test setup: the printed command name is fixed to "cra" so older tests do not depend on the machine.
The real derivation is tested in test_cli_name.py (which switches this fixed value off)."""
import pytest

from src import cli_name


@pytest.fixture(autouse=True)
def _fixed_command_name():
    cli_name.set_override("cra")
    yield
    cli_name.set_override(None)
