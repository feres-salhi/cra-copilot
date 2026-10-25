"""Phase 3, piece 1: the human-facing label "REPORT CASE" is now "POSSIBLE REPORT CASE (...)" (PLAN.md section g).

The internal action name REPORT_CASE is unchanged on purpose: only the text people read changes.
"""

import re
from pathlib import Path

from src import matcher
from tests.test_cli_run import run_cli
from tests.test_status_and_run_safety import put_run, status

LABEL = "POSSIBLE REPORT CASE (a human decides if it is reportable under the CRA)"


def test_the_run_output_uses_the_new_label(tmp_path, capsys):
    assert run_cli(tmp_path) == 3  # the exit code does not change
    out = capsys.readouterr().out
    assert f"[{LABEL}] log4j-core 2.14.1" in out
    assert not [line for line in out.splitlines() if line.startswith("[REPORT CASE")]
    assert "24-hour" in out  # the urgency cue stays in the run output


def test_the_status_warning_uses_the_new_label(tmp_path):
    put_run(tmp_path, report_cases=2)
    lines, ok = status(tmp_path)
    assert not ok
    assert any("2 POSSIBLE REPORT CASE" in line for line in lines)


def test_no_text_in_src_still_says_plain_report_case():
    for path in (Path(__file__).parent.parent / "src").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"(?<!POSSIBLE )REPORT CASE", text), path


def test_the_internal_action_name_is_unchanged():
    assert matcher.action_for(matcher.AFFECTED, True) == "REPORT_CASE"
