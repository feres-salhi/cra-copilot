"""Phase 4 piece 6: scripts/register-schedule.ps1 and scripts/unregister-schedule.ps1.

These tests only READ the scripts (and let PowerShell's parser check the syntax, which runs nothing). The scripts themselves
are never run here: they change Windows settings, and Fares registers the task himself.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).parent.parent / "scripts"
REGISTER = SCRIPTS / "register-schedule.ps1"
UNREGISTER = SCRIPTS / "unregister-schedule.ps1"


def text(path):
    return path.read_text(encoding="utf-8")


def code_only(path):
    """The script without comment lines and without the help block."""
    body = re.sub(r"<#.*?#>", "", text(path), flags=re.S)
    return "\n".join(line for line in body.splitlines() if not line.strip().startswith("#"))


def test_both_scripts_and_the_readme_exist():
    assert REGISTER.is_file() and UNREGISTER.is_file() and (SCRIPTS / "README.md").is_file()


@pytest.mark.parametrize("path", [REGISTER, UNREGISTER])
def test_scripts_are_plain_ascii_so_windows_powershell_reads_them_right(path):
    path.read_bytes().decode("ascii")


@pytest.mark.skipif(shutil.which("powershell") is None, reason="Windows PowerShell is not available")
@pytest.mark.parametrize("path", [REGISTER, UNREGISTER])
def test_powershell_can_parse_the_scripts(path):
    # ParseFile only reads the file and reports syntax errors. It runs nothing.
    command = ("$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile("
               f"'{path}', [ref]$null, [ref]$e); $e.Count")
    done = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                          capture_output=True, text=True, timeout=60)
    assert done.stdout.strip() == "0", done.stdout + done.stderr


def test_register_runs_cra_run_every_4_hours_with_a_30_minute_limit():
    code = code_only(REGISTER)
    assert "-RepetitionInterval (New-TimeSpan -Hours 4)" in code
    settings_line = next(line for line in code.splitlines() if line.startswith("$settings = "))
    assert "New-ScheduledTaskSettingsSet" in settings_line and "-ExecutionTimeLimit (New-TimeSpan -Minutes 30)" in settings_line
    trigger_line = next(line for line in code.splitlines() if line.startswith("$trigger = "))
    assert "-RepetitionInterval (New-TimeSpan -Hours 4)" in trigger_line
    assert "-m src run" in code and "--sbom" in code and "--config" in code
    assert "-MultipleInstances IgnoreNew" in code  # a run that is still going is never started twice
    assert "-WorkingDirectory" in code


def test_register_uses_the_current_user_without_a_password_and_without_admin_rights():
    code = code_only(REGISTER)
    assert "-LogonType Interactive" in code and "-RunLevel Limited" in code
    assert "$env:USERNAME" in code
    lowered = code.lower()
    for forbidden in ("-password", "runlevel highest", "-userid \"system\"", "nt authority", "localsystem", "-runasadministrator"):
        assert forbidden not in lowered


def test_register_does_not_replace_an_existing_task_and_supports_whatif():
    code = code_only(REGISTER)
    assert "SupportsShouldProcess" in code and "ShouldProcess" in code
    assert "Get-ScheduledTask" in code and "already exists" in code
    guard = code.index("$PSCmdlet.ShouldProcess")
    assert code.index("Register-ScheduledTask") > guard  # the registering line sits inside the guarded block
    assert code[guard:].count("{") >= 1 and code.index("{", guard) < code.index("Register-ScheduledTask")
    assert "Register-ScheduledTask" not in code[:guard]


def test_register_changes_nothing_else_on_the_computer():
    code = code_only(REGISTER)
    for forbidden in ("Set-ExecutionPolicy", "Set-ItemProperty", "New-ItemProperty", "reg add", "schtasks", "netsh", "Set-Service",
                      "Stop-Service", "Remove-Item", "Invoke-WebRequest", "Invoke-Expression", "iex ", "Start-Process"):
        assert forbidden.lower() not in code.lower(), forbidden
    assert code.count("Register-ScheduledTask") == 1


def test_register_does_not_start_the_task_itself():
    assert "Start-ScheduledTask" not in code_only(REGISTER)


def test_both_scripts_use_the_same_task_name_and_unregister_touches_only_that_task():
    names = [re.search(r'\$TaskName\s*=\s*"([^"]+)"', code_only(p)).group(1) for p in (REGISTER, UNREGISTER)]
    assert names[0] == names[1] and names[0].startswith("CRA Copilot")
    code = code_only(UNREGISTER)
    assert code.count("Unregister-ScheduledTask") == 1 and "-TaskName $TaskName" in code
    assert "SupportsShouldProcess" in code
    assert "Get-ScheduledTask | " not in code and "*" not in code.replace("*>", "")  # no wildcard, no "all tasks"


def test_the_readme_explains_both_scripts_in_simple_words_and_that_they_were_not_run():
    readme = text(SCRIPTS / "README.md")
    for needle in ("register-schedule.ps1", "unregister-schedule.ps1", "every 4 hours", "30 minutes", "-WhatIf",
                   "cra status", "Task Scheduler"):
        assert needle in readme, needle
    assert "exit code" in readme.lower()  # why "Last Run Result" may show 1 or 3 and that this is normal
