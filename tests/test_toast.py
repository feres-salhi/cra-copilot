"""Q1 piece 2: the Windows toast. No test here ever shows a notification: a fake runner stands in for PowerShell."""

import base64
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from src import alerts, toast

TITLE = "CRA Copilot alert"
BODY = "New possible report case: CVE-2021-44228 (case-0123456789ab). Check the 24-hour deadline."


class Runner:
    def __init__(self, returncode=0, error=None):
        self.returncode = returncode
        self.error = error
        self.calls = []

    def __call__(self, cmd, **kwargs):
        self.calls.append((cmd, kwargs))
        if self.error:
            raise self.error
        return SimpleNamespace(returncode=self.returncode, stdout=b"", stderr=b"")


@pytest.fixture
def windows(monkeypatch, tmp_path):
    """A pretend Windows folder with a powershell.exe file, so the path check passes on any machine."""
    exe = tmp_path / "Windows" / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"")
    monkeypatch.setenv("SystemRoot", str(tmp_path / "Windows"))
    return exe


def show(runner, title=TITLE, body=BODY):
    return toast.show(title, body, runner=runner, platform="win32")


def test_a_good_toast_runs_the_full_path_of_windows_powershell_without_a_shell(windows):
    runner = Runner()
    assert show(runner) is True
    (cmd, kwargs), = runner.calls
    assert cmd[0] == str(windows) and os.path.isabs(cmd[0])
    assert isinstance(cmd, list) and not kwargs.get("shell")
    assert "-NoProfile" in cmd and "-NonInteractive" in cmd and "-EncodedCommand" in cmd
    assert kwargs["timeout"] <= 30


def test_the_child_has_no_input_and_no_console_window(windows):
    runner = Runner()
    show(runner)
    kwargs = runner.calls[0][1]
    assert kwargs["stdin"] is subprocess.DEVNULL
    assert kwargs["creationflags"] == getattr(subprocess, "CREATE_NO_WINDOW", 0)


def test_the_text_travels_as_data_never_inside_the_command(windows):
    runner = Runner()
    show(runner)
    (cmd, kwargs), = runner.calls
    joined = " ".join(cmd)
    decoded = base64.b64decode(cmd[cmd.index("-EncodedCommand") + 1]).decode("utf-16-le")
    for text in ("CVE-2021-44228", "case-0123456789ab", "possible report case"):
        assert text not in joined and text not in decoded
    assert kwargs["env"]["CRA_TOAST_BODY"] == BODY and kwargs["env"]["CRA_TOAST_TITLE"] == TITLE


def test_the_powershell_script_is_the_same_fixed_text_for_every_alert(windows):
    first, second = Runner(), Runner()
    show(first)
    show(second, body="Test notification. If you can read this, alerts work on this computer.")
    assert first.calls[0][0] == second.calls[0][0]


def test_the_child_gets_only_a_short_list_of_environment_variables(windows, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "should-not-be-passed")
    monkeypatch.setenv("SECRET_THING", "x")
    runner = Runner()
    show(runner)
    env = runner.calls[0][1]["env"]
    assert "GEMINI_API_KEY" not in env and "SECRET_THING" not in env
    assert set(env) <= set(toast.PASSED_VARIABLES) | {"CRA_TOAST_TITLE", "CRA_TOAST_BODY"}


@pytest.mark.parametrize("evil", ["x | calc.exe", "x\ncalc", "$(calc)", "<b>x</b>", "`calc`", "it's", 'say "x"', "a&b", "100%", "x" * 400, "", "tab\there", "ä"])
def test_text_that_is_not_strictly_safe_is_refused_and_powershell_is_not_started(windows, evil):
    runner = Runner()
    assert show(runner, body=evil) is False
    assert show(runner, title=evil) is False
    assert runner.calls == []


def test_a_failing_powershell_gives_false_not_a_crash(windows):
    assert show(Runner(returncode=1)) is False
    assert show(Runner(error=subprocess.TimeoutExpired("x", 1))) is False
    assert show(Runner(error=OSError("no"))) is False
    assert show(Runner(error=RuntimeError("odd"))) is False


def test_other_systems_do_not_try(windows):
    runner = Runner()
    assert toast.show(TITLE, BODY, runner=runner, platform="linux") is False
    assert runner.calls == []


def test_a_missing_powershell_file_gives_false(monkeypatch, tmp_path):
    monkeypatch.setenv("SystemRoot", str(tmp_path / "nowhere"))
    runner = Runner()
    assert show(runner) is False and runner.calls == []


def test_under_pytest_the_real_runner_is_refused(windows):
    """Even if a test forgot to pass a fake runner, the real PowerShell is never started."""
    assert toast.show(TITLE, BODY, platform="win32") is False


def test_the_default_notifier_in_tests_is_the_fake_one():
    notifier = alerts.default_notifier()
    assert notifier is not toast.show


def test_without_an_override_the_default_notifier_is_the_toast(monkeypatch):
    monkeypatch.setattr(alerts, "_override", None)
    assert alerts.default_notifier() is toast.show


@pytest.mark.skipif(sys.platform != "win32", reason="needs Windows PowerShell")
def test_the_fixed_script_is_valid_powershell_and_is_only_parsed_not_run(tmp_path):
    parse = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseInput($env:S,[ref]$t,[ref]$e);"
             "if($e.Count -gt 0){exit 5}")
    exe = os.path.join(os.environ["SystemRoot"], "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    env = {"SystemRoot": os.environ["SystemRoot"], "S": toast.SCRIPT}
    result = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", parse], env=env,
                            capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr


def test_a_network_share_as_system_root_is_refused(monkeypatch, tmp_path):
    for bad in ("\\\\evil\\share\\Windows", "relative\\Windows", "//evil/share", ""):
        monkeypatch.setenv("SystemRoot", bad)
        runner = Runner()
        assert show(runner) is False and runner.calls == []


def test_the_script_pattern_and_the_python_pattern_are_the_same():
    start = toast.SCRIPT.index("$ok = '") + len("$ok = '")
    script_pattern = toast.SCRIPT[start:toast.SCRIPT.index("'", start)]
    assert script_pattern == r"\A" + alerts.SAFE_TEXT.pattern + r"\z"


def test_toast_py_only_starts_powershell_in_the_one_safe_way():
    """subprocess may be used for exactly one thing: the `run` function as the default runner, called with a list."""
    import ast
    from pathlib import Path
    tree = ast.parse((Path(toast.__file__)).read_text(encoding="utf-8"))
    uses = [n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "subprocess"]
    assert {n.attr for n in uses} <= {"run", "DEVNULL", "CREATE_NO_WINDOW"}
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "shell":
            assert isinstance(node.value, ast.Constant) and node.value.value is False
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "runner":
            assert isinstance(node.args[0], ast.List)
