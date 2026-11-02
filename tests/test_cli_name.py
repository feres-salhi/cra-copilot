"""Improvement 2: every command the tool suggests is printed in the form that works on THIS computer."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from src import cli_name

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _real_derivation():
    cli_name.set_override(None)
    yield


def test_started_as_python_dash_m_src_inside_the_project_gives_the_relative_python_form():
    cwd = os.path.join(os.sep, "proj")
    exe = os.path.join(cwd, ".venv", "Scripts", "python.exe")
    prefix = cli_name.command_prefix(executable=exe, argv0=os.path.join(cwd, "src", "__main__.py"), cwd=cwd)
    assert prefix == os.path.join(".venv", "Scripts", "python") + " -m src"


def test_python_outside_the_project_folder_is_shown_with_its_full_path():
    cwd = os.path.join(os.sep, "proj")
    exe = os.path.join(os.sep, "tools", "py", "python.exe")
    assert cli_name.command_prefix(executable=exe, argv0="x", cwd=cwd) == exe[:-4] + " -m src"


def test_a_path_with_blanks_is_quoted_for_powershell():
    cwd = os.path.join(os.sep, "my proj")
    exe = os.path.join(os.sep, "my tools", "python.exe")
    prefix = cli_name.command_prefix(executable=exe, argv0="x", cwd=cwd)
    assert prefix.startswith("& '") and prefix.endswith("' -m src") and "my tools" in prefix


@pytest.mark.parametrize("argv0", ["cra", "cra.exe", os.path.join("bin", "cra"), os.path.join("Scripts", "CRA.EXE")])
def test_started_through_a_real_cra_program_the_short_form_is_kept(argv0):
    assert cli_name.command_prefix(executable="python.exe", argv0=argv0, cwd=os.getcwd()) == "cra"


def test_command_joins_words_and_never_adds_unsafe_text():
    cli_name.set_override("cra")
    assert cli_name.command("approve", "case-abc") == "cra approve case-abc"
    assert cli_name.command("run") == "cra run"


def test_the_override_is_for_tests_only_and_can_be_cleared():
    cli_name.set_override("zzz")
    assert cli_name.command("run") == "zzz run"
    cli_name.set_override(None)
    assert cli_name.command("run") != "zzz run"


def test_end_to_end_the_status_message_uses_the_python_form_when_started_with_dash_m(tmp_path):
    """A real child process: `python -m src status` on an empty runs folder must suggest a command that really works."""
    out = subprocess.run([sys.executable, "-m", "src", "status", "--runs", str(tmp_path)], cwd=ROOT,
                         capture_output=True, text=True, timeout=60).stdout
    assert "-m src run" in out and "`cra run`" not in out


@pytest.mark.parametrize("bad", ["x;calc", "a$(calc)b", "a`b", "it's", "a&b", "a(b)", 'q"q', "a,b", "a@b", "a%b", "a\nb"])
def test_a_python_path_with_special_characters_is_never_put_into_the_command(bad):
    cwd = os.path.join(os.sep, "proj")
    for exe in (os.path.join(os.sep, bad, "python.exe"), os.path.join(cwd, bad, "python.exe")):
        assert cli_name.command_prefix(executable=exe, argv0="x", cwd=cwd) == "python -m src"


def test_python_directly_in_the_current_folder_gets_a_dot_slash():
    cwd = os.path.join(os.sep, "proj")
    prefix = cli_name.command_prefix(executable=os.path.join(cwd, "python.exe"), argv0="x", cwd=cwd)
    assert prefix == os.curdir + os.sep + "python -m src"
