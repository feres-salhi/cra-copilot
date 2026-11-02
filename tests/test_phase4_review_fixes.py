"""Phase 4 team meeting, round 1: the tool's own clock stays visible after drafting; no false warning at approval;
a stale KEV list is warned about; one broken case does not hide the others; risky paths get no pasted command."""

from datetime import timedelta

import pytest

from src import case_commands, cases
from tests.test_cli_approve import approve, good_answers
from tests.test_cli_draft import GOOD_BEFORE_RUN, Keyboard, LATER, draft
from tests.test_cli_run import NOW, run_cli
from tests.test_cli_run_open_cases import make_case, open_part, run_at

AFTER_RUN = "2026-10-21 13:00 UTC"          # one hour after the first run (12:00 UTC)
REASON = "The security officer was away on a business trip"


def late_world(tmp_path):
    run_cli(tmp_path, extra=["--cases", str(tmp_path / "cases")])
    (run_file,) = (tmp_path / "runs").glob("*.json")
    assert draft((tmp_path, run_file), Keyboard(AFTER_RUN, REASON, "yes")) == 0
    (case_dir,) = (tmp_path / "cases").iterdir()
    return tmp_path, case_dir.name


# ---------------------------------------------------------------- the tool's own clock


def test_approval_shows_the_reason_and_the_tools_own_deadline(tmp_path, capsys):
    world = late_world(tmp_path)
    capsys.readouterr()
    assert approve(world, Keyboard(*good_answers(world[1]))) == 0
    out = capsys.readouterr().out
    assert REASON in out
    assert "By the tool's own clock" in out and "22 Oct 2026, 14:00 (Berlin, CEST) = 22 Oct 2026 12:00 UTC" in out
    assert "LATER than the tool's own clock allows" in out
    assert "LATER than the first run" in out  # the same loud warning as when the case was drafted


def test_approval_no_longer_claims_that_no_run_record_was_found(tmp_path, capsys):
    world = late_world(tmp_path)
    capsys.readouterr()
    approve(world, Keyboard(*good_answers(world[1])))
    assert "No sealed run record" not in capsys.readouterr().out


def test_an_ordinary_approval_has_no_warning_about_the_clock(tmp_path, capsys):
    world = make_case(tmp_path), None
    world = (tmp_path, world[0])
    capsys.readouterr()
    assert approve(world, Keyboard(*good_answers(world[1]))) == 0
    out = capsys.readouterr().out
    assert "By the tool's own clock" in out
    assert "LATER than the tool's own clock" not in out and "No sealed run record" not in out and "WARNING:" not in out


def test_the_open_list_uses_the_earlier_of_the_two_deadlines(tmp_path, capsys):
    late_world(tmp_path)
    # typed deadline: 22 Oct 13:00 UTC. The tool's own clock: 22 Oct 12:00 UTC. At 12:30 only the second has passed.
    _, out = run_at(tmp_path, NOW + timedelta(days=1, minutes=30), capsys)
    tail = open_part(out)
    assert "NOTE: by the tool's own clock" in tail and "22 Oct 2026 12:00 UTC" in tail
    assert "OVERDUE" in tail and "ALREADY PASSED" in tail


def test_the_open_list_has_no_note_when_the_typed_time_is_not_later(tmp_path, capsys):
    make_case(tmp_path)
    _, out = run_at(tmp_path, LATER + timedelta(hours=1), capsys)
    assert "NOTE: by the tool's own clock" not in open_part(out)


# ---------------------------------------------------------------- an old saved KEV list


def test_draft_and_approve_warn_about_an_old_kev_list(tmp_path, capsys):
    run_cli(tmp_path, extra=["--cases", str(tmp_path / "cases")])
    (run_file,) = (tmp_path / "runs").glob("*.json")
    capsys.readouterr()
    assert draft((tmp_path, run_file), Keyboard(GOOD_BEFORE_RUN, "yes"), now=lambda: NOW + timedelta(days=5)) == 0
    assert "the saved KEV list is 5 days old" in capsys.readouterr().out
    (case_dir,) = (tmp_path / "cases").iterdir()
    assert approve((tmp_path, case_dir.name), Keyboard(*good_answers(case_dir.name)), now=lambda: NOW + timedelta(days=5)) == 0
    assert "the saved KEV list is 5 days old" in capsys.readouterr().out


def test_a_fresh_kev_list_gets_no_age_warning(tmp_path, capsys):
    world = (tmp_path, make_case(tmp_path))
    capsys.readouterr()
    approve(world, Keyboard(*good_answers(world[1])))
    assert "days old" not in capsys.readouterr().out


def test_age_warning_unit():
    now = NOW
    assert case_commands._kev_age_warning({"downloaded_at": (now - timedelta(days=3)).isoformat()}, now) is None
    assert "4 days old" in case_commands._kev_age_warning({"downloaded_at": (now - timedelta(days=4)).isoformat()}, now)
    assert "not known" in case_commands._kev_age_warning({}, now)
    assert "not known" in case_commands._kev_age_warning({"downloaded_at": "yesterday"}, now)


# ---------------------------------------------------------------- one broken case, risky paths


def test_one_broken_case_does_not_hide_the_others(tmp_path, capsys, monkeypatch):
    make_case(tmp_path)
    real = cases.approval_state
    broken_id = cases.list_cases(tmp_path / "cases")[0][0].case_id

    # a second, healthy case
    from datetime import datetime, timezone
    from src import report_facts, report_writer
    first = cases.list_cases(tmp_path / "cases")[0][0]
    facts = dict(first.facts, version="2.0.0")
    facts["title"] = report_facts._titles(facts["product_name"], facts["component"], facts["version"], facts["cve_id"])
    draft_ = report_writer.build_draft(facts, None)
    healthy = cases.create_case(tmp_path / "cases", facts, draft_.reports, draft_.check, draft_.source,
                                cases.new_meta(NOW, {"run_file": "x.json"}))

    def flaky(case):
        if case.case_id == broken_id:
            raise RuntimeError("boom")
        return real(case)

    monkeypatch.setattr(cases, "approval_state", flaky)
    _, out = run_at(tmp_path, LATER, capsys)
    tail = open_part(out)
    assert f"the case {broken_id} could not be judged" in tail
    assert healthy in tail and "PENDING" in tail


@pytest.mark.parametrize("bad", ["C:\\data\\runs\\", "C:\\a$b\\run.json", "C:\\a`b\\run.json", 'C:\\a"b\\run.json'])
def test_no_pasted_command_for_a_path_that_ends_in_a_backslash_or_has_shell_characters(tmp_path, capsys, bad):
    case_commands.print_open_cases(tmp_path / "cases", NOW, {"manufacturer": "M GmbH", "product_name": "P"},
                                   [{"component": "c", "version": "1", "exploited_cve": "CVE-2021-44228"}],
                                   bad, tmp_path / "s.json", tmp_path / "c.json")
    out = capsys.readouterr().out
    assert "no ready-made command is shown" in out and "cra draft --run" not in out
