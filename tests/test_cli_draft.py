"""Phase 4 piece 2: `cra draft` creates a PENDING case from a possible report case of a sealed run (offline, fake keyboard)."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from src import cases
from src.cli import main
from tests.test_cli_run import NOW as RUN_TIME, run_cli

LATER = RUN_TIME + timedelta(hours=2)  # the clock when the human drafts (two hours after the run)


class Keyboard:
    """A fake keyboard: gives the prepared answers in order and remembers every question."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.questions = []

    def __call__(self, question):
        self.questions.append(question)
        if not self.answers:
            raise EOFError("no more answers")
        return self.answers.pop(0)


@pytest.fixture
def world(tmp_path):
    """A real (fake-network) run on the demo product: sealed run file, saved KEV list, empty cases folder."""
    run_cli(tmp_path)
    (run_file,) = (tmp_path / "runs").glob("*.json")
    return tmp_path, run_file


def draft(world, keyboard, extra=(), now=lambda: LATER, run_file=None):
    tmp_path, default_run = world
    args = ["draft", "--run", str(run_file or default_run), "--cve", "CVE-2021-44228", "--cases", str(tmp_path / "cases"),
            "--cache", str(tmp_path / "cache"), "--runs", str(tmp_path / "runs"), "--evidence", str(tmp_path / "evidence"), *extra]
    return main(args, ask=keyboard, now=now)


def only_case(tmp_path):
    found, unreadable = cases.list_cases(tmp_path / "cases")
    assert unreadable == [] and len(found) == 1
    return found[0]


GOOD_BEFORE_RUN = "2026-10-21 11:00 UTC"   # before the first run (12:00 UTC): no reason needed
AFTER_RUN = "2026-10-21 13:00 UTC"          # after the first run: loud warning, a reason is needed


def test_draft_creates_a_pending_case_with_a_deadline_24_hours_later(world, capsys):
    tmp_path, _ = world
    capsys.readouterr()
    keyboard = Keyboard(GOOD_BEFORE_RUN, "yes")
    assert draft(world, keyboard) == 0
    out = capsys.readouterr().out
    case = only_case(tmp_path)
    assert case.meta["status"] == "PENDING"
    assert case.facts["awareness_time_utc"] == "2026-10-21T11:00:00+00:00"
    assert case.facts["deadline_utc"] == "2026-10-22T11:00:00+00:00"
    assert case.check["status"] == "PASS"
    assert "PENDING" in out and "22 Oct 2026, 13:00 (Berlin, CEST)" in out
    assert "Nothing was sent" in out
    assert case.case_id in out


def test_draft_shows_what_the_tool_itself_observed(world, capsys):
    capsys.readouterr()
    draft(world, Keyboard(GOOD_BEFORE_RUN, "yes"))
    out = capsys.readouterr().out
    assert "First run that found this case" in out
    assert "KEV dateAdded 2021-12-10" in out
    assert "KEV list saved on this computer at" in out
    assert "stores no vendor or product text" in out  # honest note: those texts are not stored
    assert "Runs folder searched:" in out


def test_a_time_later_than_the_first_run_needs_a_typed_reason_and_is_loud(world, capsys):
    tmp_path, _ = world
    capsys.readouterr()
    keyboard = Keyboard(AFTER_RUN, "The security officer was on holiday", "yes")
    assert draft(world, keyboard) == 0
    out = capsys.readouterr().out
    assert "LATER than the first run" in out
    case = only_case(tmp_path)
    assert case.meta["origin"]["awareness"]["reason"] == "The security officer was on holiday"
    assert any("reason" in q.lower() for q in keyboard.questions)


def test_a_late_time_without_a_usable_reason_creates_nothing(world, capsys):
    tmp_path, _ = world
    for bad in ("", "   ", "x" * 500, "tab\there", "too short"):
        keyboard = Keyboard(AFTER_RUN, bad, bad, bad, "yes")
        assert draft(world, keyboard) == 1
        assert keyboard.answers == ["yes"]  # the final question was never reached
        assert not (tmp_path / "cases").exists() or list((tmp_path / "cases").iterdir()) == []


def test_the_future_is_refused_and_nothing_is_created(world, capsys):
    tmp_path, _ = world
    capsys.readouterr()
    keyboard = Keyboard("2026-10-21 15:00 UTC", "2026-10-21 15:00 UTC", "2026-10-21 15:00 UTC")
    assert draft(world, keyboard) == 1
    out = capsys.readouterr().out
    assert out.count("in the future") == 3 and "Cancelled" in out
    assert not (tmp_path / "cases").exists() or list((tmp_path / "cases").iterdir()) == []


def test_earlier_than_the_kev_date_is_refused(world, capsys):
    capsys.readouterr()
    assert draft(world, Keyboard(*["2021-12-09 08:00 UTC"] * 3)) == 1
    out = capsys.readouterr().out
    assert "earlier than the data allowed" in out and "2021-12-10" in out


def test_a_bad_format_is_asked_again_and_then_gives_up(world, capsys):
    capsys.readouterr()
    keyboard = Keyboard("tomorrow", "11:00", "2026-10-21 11:00")
    assert draft(world, keyboard) == 1
    assert "Cancelled" in capsys.readouterr().out
    assert len(keyboard.questions) == 3


def test_a_first_bad_answer_does_not_stop_a_second_good_one(world):
    tmp_path, _ = world
    assert draft(world, Keyboard("oops", GOOD_BEFORE_RUN, "yes")) == 0
    only_case(tmp_path)


def test_without_a_yes_nothing_is_created(world, capsys):
    tmp_path, _ = world
    for answer in ("no", "", "y", "YES", "yes please"):
        assert draft(world, Keyboard(GOOD_BEFORE_RUN, answer)) == 1
    assert not (tmp_path / "cases").exists() or list((tmp_path / "cases").iterdir()) == []


def test_a_piped_input_or_scheduled_task_is_not_a_human(world, capsys):
    tmp_path, run_file = world
    args = ["draft", "--run", str(run_file), "--cve", "CVE-2021-44228", "--cases", str(tmp_path / "cases"),
            "--cache", str(tmp_path / "cache"), "--runs", str(tmp_path / "runs"), "--evidence", str(tmp_path / "evidence")]
    assert main(args, now=lambda: LATER) == 1  # pytest's stdin is not a keyboard
    assert not (tmp_path / "cases").exists() or list((tmp_path / "cases").iterdir()) == []


@pytest.mark.parametrize("flag", [["--yes"], ["--awareness", "2026-10-21 11:00 UTC"], ["--force"], ["--no-input"], ["--send"], ["--reason", "x"]])
def test_no_flag_can_skip_the_questions(world, flag):
    with pytest.raises(SystemExit):
        draft(world, Keyboard(), extra=flag)


def test_the_same_case_is_not_drafted_twice(world, capsys):
    tmp_path, _ = world
    assert draft(world, Keyboard(GOOD_BEFORE_RUN, "yes")) == 0
    capsys.readouterr()
    assert draft(world, Keyboard(GOOD_BEFORE_RUN, "yes")) == 1
    assert "already exists" in capsys.readouterr().out


def test_an_unsealed_or_missing_run_is_rejected(world, tmp_path):
    base, run_file = world
    forged = json.loads(run_file.read_text(encoding="utf-8"))
    forged["report_cases"] = 7
    fake = tmp_path / "fake.json"
    fake.write_text(json.dumps(forged), encoding="utf-8")
    assert draft(world, Keyboard(), run_file=fake) == 2
    assert draft(world, Keyboard(), run_file=tmp_path / "missing.json") == 2


def test_a_run_without_a_possible_report_case_says_so(tmp_path, capsys):
    from tests.test_cli_run import write_sbom
    sbom = write_sbom(tmp_path, ["pkg:pypi/requests@2.32.0"])
    run_cli(tmp_path, sbom=sbom)
    (run_file,) = (tmp_path / "runs").glob("*.json")
    capsys.readouterr()
    code = main(["draft", "--run", str(run_file), "--cases", str(tmp_path / "cases"), "--cache", str(tmp_path / "cache"),
                 "--runs", str(tmp_path / "runs"), "--evidence", str(tmp_path / "evidence")], ask=Keyboard(), now=lambda: LATER)
    assert code == 0 and "No POSSIBLE REPORT CASE" in capsys.readouterr().out


def test_without_the_saved_kev_list_no_case_is_drafted(world, capsys):
    tmp_path, _ = world
    (tmp_path / "cache" / "kev" / "kev-saved.json").unlink()
    capsys.readouterr()
    assert draft(world, Keyboard(GOOD_BEFORE_RUN, "yes")) == 1
    assert "cannot be built" in capsys.readouterr().out
    assert not (tmp_path / "cases").exists() or list((tmp_path / "cases").iterdir()) == []


def test_a_passed_deadline_is_a_loud_warning_but_the_case_is_still_drafted(world, capsys):
    capsys.readouterr()
    assert draft(world, Keyboard(GOOD_BEFORE_RUN, "yes"), now=lambda: RUN_TIME + timedelta(days=3)) == 0
    assert "ALREADY PASSED" in capsys.readouterr().out


def test_a_berlin_time_in_the_repeated_hour_is_asked_again(world, capsys):
    capsys.readouterr()
    keyboard = Keyboard("2026-10-25 02:30 Berlin", "yes")
    assert draft(world, keyboard, now=lambda: RUN_TIME + timedelta(days=10)) == 1  # one bad answer, then "yes" is not a time
    assert "happens twice" in capsys.readouterr().out


def test_several_cases_ask_which_one(world, capsys):
    tmp_path, run_file = world
    args = ["draft", "--run", str(run_file), "--cases", str(tmp_path / "cases"), "--cache", str(tmp_path / "cache"),
            "--runs", str(tmp_path / "runs"), "--evidence", str(tmp_path / "evidence")]
    keyboard = Keyboard("99", "1", GOOD_BEFORE_RUN, "yes")
    code = main(args, ask=keyboard, now=lambda: LATER)
    out = capsys.readouterr().out
    assert code == 0 and "1)" in out and "2)" in out
    only_case(tmp_path)


def test_the_draft_file_has_both_languages_and_says_not_approved(world):
    tmp_path, _ = world
    draft(world, Keyboard(GOOD_BEFORE_RUN, "yes"))
    case = only_case(tmp_path)
    assert "NOT APPROVED, NOT SENT" in case.reports["en"] and "NICHT FREIGEGEBEN, NICHT GESENDET" in case.reports["de"]
    assert "log4j-core 2.14.1" in case.reports["en"]


def test_the_case_records_where_it_came_from(world):
    tmp_path, run_file = world
    draft(world, Keyboard(GOOD_BEFORE_RUN, "yes"))
    origin = only_case(tmp_path).meta["origin"]
    assert origin["run_file"] == run_file.name
    assert len(origin["run_seal"]) == 64
    assert origin["awareness"]["typed"] == GOOD_BEFORE_RUN
    assert origin["first_found"]["file"] == run_file.name
    assert origin["earliest_allowed"]["reason"] == "KEV dateAdded 2021-12-10"
    assert origin["kev"]["date_added"] == "2021-12-10"
