"""Q5: `cra close <case-id>`. A human marks an APPROVED case as submitted by hand. The tool sends nothing and cannot check it."""

import json
from datetime import timedelta

import pytest

from src import cases
from src.cli import main
from tests.test_cli_approve import NAME, approve, good_answers
from tests.test_cli_draft import GOOD_BEFORE_RUN, Keyboard, LATER, draft
from tests.test_cli_run import NOW, run_cli
from tests.test_cli_run_open_cases import make_case, open_part, run_at


def close(tmp_path, case_id, keyboard, now=lambda: LATER + timedelta(hours=3)):
    return main(["close", case_id, "--cases", str(tmp_path / "cases")], ask=keyboard, now=now)


def approved_case(tmp_path):
    case_id = make_case(tmp_path)
    assert approve((tmp_path, case_id), Keyboard(*good_answers(case_id))) == 0
    return case_id


def good(case_id):
    return [case_id, "yes", NAME]


def test_an_approved_case_can_be_closed_by_a_human(tmp_path, capsys):
    case_id = approved_case(tmp_path)
    assert close(tmp_path, case_id, Keyboard(*good(case_id))) == 0
    out = capsys.readouterr().out
    assert "marked as submitted" in out and "Nothing was sent" in out
    assert (tmp_path / "cases" / case_id / "closed.json").is_file()
    line = (tmp_path / "cases" / "closed.log").read_text(encoding="utf-8").splitlines()
    assert len(line) == 1 and case_id in line[0] and NAME in line[0]


def test_a_pending_case_cannot_be_closed(tmp_path, capsys):
    case_id = make_case(tmp_path)
    assert close(tmp_path, case_id, Keyboard(*good(case_id))) == 1
    assert "only an approved case" in capsys.readouterr().out.lower()
    assert not (tmp_path / "cases" / case_id / "closed.json").exists()


@pytest.mark.parametrize("answers", [["wrong-id", "yes", NAME], None, ["{id}", "y", NAME], ["{id}", "yes", ""], ["{id}", "yes", "bad\x07name"]])
def test_wrong_or_missing_answers_cancel(tmp_path, answers):
    case_id = approved_case(tmp_path)
    keyboard = Keyboard() if answers is None else Keyboard(*[a.replace("{id}", case_id) for a in answers])
    assert close(tmp_path, case_id, keyboard) == 1
    assert not (tmp_path / "cases" / case_id / "closed.json").exists()


def test_a_closed_case_leaves_the_open_list_and_closing_again_changes_nothing(tmp_path, capsys):
    case_id = approved_case(tmp_path)
    close(tmp_path, case_id, Keyboard(*good(case_id)))
    _, out = run_at(tmp_path, LATER + timedelta(hours=1), capsys)
    assert case_id not in open_part(out)
    capsys.readouterr()
    assert close(tmp_path, case_id, Keyboard()) == 0
    assert "already marked" in capsys.readouterr().out
    assert len((tmp_path / "cases" / "closed.log").read_text(encoding="utf-8").splitlines()) == 1


def test_an_approved_case_after_its_deadline_stays_listed_until_it_is_closed(tmp_path, capsys):
    case_id = approved_case(tmp_path)
    _, out = run_at(tmp_path, LATER + timedelta(days=3), capsys)
    tail = open_part(out)
    assert case_id in tail and "cra close" in tail and "OVERDUE" in tail
    close(tmp_path, case_id, Keyboard(*good(case_id)), now=lambda: LATER + timedelta(days=3))
    _, out = run_at(tmp_path, LATER + timedelta(days=3, hours=1), capsys)
    assert case_id not in open_part(out)


def test_a_closed_mark_does_not_count_when_the_approved_text_changed(tmp_path, capsys):
    case_id = approved_case(tmp_path)
    close(tmp_path, case_id, Keyboard(*good(case_id)))
    (tmp_path / "cases" / case_id / "approved.md").write_text("changed", encoding="utf-8")
    _, out = run_at(tmp_path, LATER + timedelta(hours=1), capsys)
    assert case_id in open_part(out) and "CHANGED" in open_part(out)


@pytest.mark.parametrize("content", ["{ not json", "[]", json.dumps({"schema": 1, "case_id": "case-000000000000"})])
def test_a_damaged_or_foreign_closed_file_does_not_hide_the_case(tmp_path, capsys, content):
    case_id = approved_case(tmp_path)
    (tmp_path / "cases" / case_id / "closed.json").write_text(content, encoding="utf-8")
    _, out = run_at(tmp_path, LATER + timedelta(hours=1), capsys)
    assert case_id in open_part(out)


def test_a_huge_closed_file_is_ignored(tmp_path, capsys):
    case_id = approved_case(tmp_path)
    (tmp_path / "cases" / case_id / "closed.json").write_bytes(b" " * (cases.MAX_FILE_BYTES + 5))
    _, out = run_at(tmp_path, LATER + timedelta(hours=1), capsys)
    assert case_id in open_part(out)


def test_an_unknown_case_id_is_rejected(tmp_path, capsys):
    assert close(tmp_path, "case-000000000000", Keyboard()) == 2
    assert close(tmp_path, "../evil", Keyboard()) == 2


def test_the_command_is_for_humans_only(tmp_path):
    import inspect
    from src import case_commands
    source = inspect.getsource(case_commands.close_command)
    assert "_ask(" in source and "--yes" not in source


def test_a_closed_json_without_its_log_line_does_not_hide_the_case(tmp_path, capsys):
    case_id = approved_case(tmp_path)
    close(tmp_path, case_id, Keyboard(*good(case_id)))
    (tmp_path / "cases" / "closed.log").unlink()
    _, out = run_at(tmp_path, LATER + timedelta(hours=1), capsys)
    assert case_id in open_part(out)


def test_a_mark_does_not_survive_a_new_approval_with_the_same_text(tmp_path, capsys):
    case_id = approved_case(tmp_path)
    close(tmp_path, case_id, Keyboard(*good(case_id)))
    case = cases.load_case(tmp_path / "cases", case_id)
    meta = dict(case.meta)
    meta["approval"] = {**meta["approval"], "approved_at": "2026-10-22T09:00:00+00:00"}  # a later approval, same approved.md
    assert cases.is_closed(case) is True
    forged = cases.Case(case.case_id, case.folder, case.facts, case.reports, case.check, meta, case.sha256)
    assert cases.is_closed(forged) is False


def test_if_the_log_cannot_be_written_the_case_stays_open_and_the_message_is_true(tmp_path, capsys):
    case_id = approved_case(tmp_path)
    (tmp_path / "cases" / "closed.log").mkdir()
    capsys.readouterr()
    assert close(tmp_path, case_id, Keyboard(*good(case_id))) == 1
    assert "stays open" in capsys.readouterr().out
    assert not (tmp_path / "cases" / case_id / "closed.json").exists()
    _, out = run_at(tmp_path, LATER + timedelta(hours=1), capsys)
    assert case_id in open_part(out)


def test_a_closed_json_with_a_wrong_hash_or_a_long_name_does_not_count(tmp_path, capsys):
    case_id = approved_case(tmp_path)
    close(tmp_path, case_id, Keyboard(*good(case_id)))
    path = tmp_path / "cases" / case_id / "closed.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    for change in ({"approved_sha256": "0" * 64}, {"closed_by": "x" * 200}):
        path.write_text(json.dumps({**data, **change}), encoding="utf-8")
        assert cases.is_closed(cases.load_case(tmp_path / "cases", case_id)) is False
