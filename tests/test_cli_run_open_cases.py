"""Phase 4 piece 5: `cra run` end to end on the demo product, ending with a short list of open cases and their deadlines."""

import json
from datetime import timedelta

import pytest

from src import cases
from src.cli import main
from tests.test_cli_approve import NAME, approve, good_answers
from tests.test_cli_draft import GOOD_BEFORE_RUN, Keyboard, LATER, draft
from tests.test_cli_run import NOW, run_cli


def run_at(tmp_path, when, capsys):
    capsys.readouterr()
    code = run_cli(tmp_path, now=lambda: when, extra=["--cases", str(tmp_path / "cases")])
    return code, capsys.readouterr().out


def open_part(out):
    assert "OPEN CASES" in out
    return out[out.index("OPEN CASES"):]


def make_case(tmp_path):
    run_cli(tmp_path, extra=["--cases", str(tmp_path / "cases")])
    (run_file,) = (tmp_path / "runs").glob("*.json")
    assert draft((tmp_path, run_file), Keyboard(GOOD_BEFORE_RUN, "yes")) == 0
    (case_dir,) = (tmp_path / "cases").iterdir()
    return case_dir.name


def test_without_any_case_the_run_says_which_possible_report_cases_still_need_a_draft(tmp_path, capsys):
    code, out = run_at(tmp_path, NOW, capsys)
    tail = open_part(out)
    assert code == 3
    assert "No open cases" in tail
    assert "WITHOUT A DRAFT" in tail and "CVE-2021-44228" in tail and "CVE-2021-45046" in tail
    assert "cra draft --run" in tail and "--cve CVE-2021-44228" in tail
    assert tail.rstrip().endswith("Nothing was sent. A human decides what happens next.")


def test_a_pending_case_is_listed_with_its_deadline_and_the_time_left(tmp_path, capsys):
    case_id = make_case(tmp_path)
    code, out = run_at(tmp_path, LATER + timedelta(hours=1), capsys)
    tail = open_part(out)
    assert case_id in tail and "PENDING" in tail
    assert "CVE-2021-44228" in tail and "log4j-core 2.14.1" in tail
    assert "22 Oct 2026, 13:00 (Berlin, CEST) = 22 Oct 2026 11:00 UTC" in tail
    assert "left" in tail and "OVERDUE" not in tail
    assert f"cra approve {case_id}" in tail
    # the drafted case is not listed as "without a draft" any more, the other one still is
    without = tail[tail.index("WITHOUT A DRAFT"):]
    assert "CVE-2021-45046" in without and "CVE-2021-44228" not in without


def test_a_passed_deadline_is_loud(tmp_path, capsys):
    make_case(tmp_path)
    _, out = run_at(tmp_path, LATER + timedelta(days=3), capsys)
    assert "OVERDUE" in open_part(out) and "ALREADY PASSED" in open_part(out)


def test_the_list_is_sorted_by_deadline_and_short(tmp_path, capsys, monkeypatch):
    make_case(tmp_path)
    root = tmp_path / "cases"
    first = cases.list_cases(root)[0][0]
    # copy the case 12 times with other awareness times: the list shows the 10 most urgent and says how many are left
    from src import report_facts, report_writer
    from datetime import datetime, timezone
    for i in range(12):
        facts = dict(first.facts, version=f"2.{i}.0")
        facts["awareness_time_utc"] = datetime(2026, 10, 21, 1 + i, 0, tzinfo=timezone.utc).isoformat()
        facts["deadline_utc"] = (datetime(2026, 10, 21, 1 + i, 0, tzinfo=timezone.utc) + timedelta(hours=24)).isoformat()
        facts["title"] = report_facts._titles(facts["product_name"], facts["component"], facts["version"], facts["cve_id"])
        draft_ = report_writer.build_draft(facts, None)
        cases.create_case(root, facts, draft_.reports, draft_.check, draft_.source, cases.new_meta(NOW, {"run_file": "x.json"}))
    _, out = run_at(tmp_path, LATER, capsys)
    tail = open_part(out)
    assert tail.count("PENDING") == 10 and "3 more open case" in tail
    first_line = [l for l in tail.splitlines() if "PENDING" in l][0]
    assert "2.0.0" in first_line  # the earliest deadline comes first


def test_an_approved_case_is_listed_while_there_is_still_time_to_submit_by_hand(tmp_path, capsys):
    case_id = make_case(tmp_path)
    assert approve((tmp_path, case_id), Keyboard(*good_answers(case_id))) == 0
    _, out = run_at(tmp_path, LATER + timedelta(hours=1), capsys)
    tail = open_part(out)
    assert case_id in tail and "APPROVED" in tail and "by hand" in tail
    _, out = run_at(tmp_path, LATER + timedelta(days=3), capsys)
    # Q5: an approved case stays listed after its deadline until a human marks it with `cra close`
    assert case_id in open_part(out) and "cra close" in open_part(out)


def test_a_case_that_changed_after_approval_is_loud(tmp_path, capsys):
    case_id = make_case(tmp_path)
    approve((tmp_path, case_id), Keyboard(*good_answers(case_id)))
    path = tmp_path / "cases" / case_id / "draft.md"
    path.write_bytes(path.read_bytes() + b" ")
    _, out = run_at(tmp_path, LATER + timedelta(hours=1), capsys)
    tail = open_part(out)
    assert case_id in tail and "CHANGED" in tail and "must be approved again" in tail


def test_an_unreadable_case_folder_is_reported_not_hidden(tmp_path, capsys):
    (tmp_path / "cases" / "case-bbbbbbbbbbbb").mkdir(parents=True)
    _, out = run_at(tmp_path, NOW, capsys)
    assert "case-bbbbbbbbbbbb" in open_part(out) and "cannot be read" in open_part(out)


def test_the_whole_chain_run_draft_approve_run(tmp_path, capsys):
    """The end-to-end story on the demo product: find, draft, approve, and the next run still shows the case."""
    code, out = run_at(tmp_path, NOW, capsys)
    assert code == 3 and "WITHOUT A DRAFT" in out
    (run_file,) = (tmp_path / "runs").glob("*.json")
    assert draft((tmp_path, run_file), Keyboard(GOOD_BEFORE_RUN, "yes")) == 0
    (case_dir,) = (tmp_path / "cases").iterdir()
    assert approve((tmp_path, case_dir.name), Keyboard(*good_answers(case_dir.name))) == 0
    code, out = run_at(tmp_path, LATER + timedelta(hours=2), capsys)
    assert code == 3  # still a possible report case in the data
    assert "APPROVED" in open_part(out)
    assert json.loads((tmp_path / "cases" / "approvals.log").read_text(encoding="utf-8"))["approver"] == NAME


def test_a_missing_cases_folder_is_fine_and_creates_nothing(tmp_path, capsys):
    _, out = run_at(tmp_path, NOW, capsys)
    assert "OPEN CASES" in out
    assert not (tmp_path / "cases").exists()


def test_a_failed_run_still_does_not_crash_the_list(tmp_path, capsys):
    class Broken:
        def __call__(self, *a, **k):
            raise OSError("network down")

    capsys.readouterr()
    code = main(["run", "--sbom", str(__import__("tests.test_cli_run", fromlist=["SBOM"]).SBOM), "--config",
                 str(__import__("tests.test_cli_run", fromlist=["CONFIG"]).CONFIG), "--cache", str(tmp_path / "cache"),
                 "--runs", str(tmp_path / "runs"), "--evidence", str(tmp_path / "evidence"), "--cases", str(tmp_path / "cases")],
                fetch=Broken(), sleep=lambda s: None, now=lambda: NOW)
    assert code == 1
    assert "RESULT INCOMPLETE" in capsys.readouterr().out


# ---------------------------------------------------------------- after the reviews


def test_the_ready_made_commands_use_the_same_folders_as_the_run(tmp_path, capsys):
    case_id = make_case(tmp_path)
    _, out = run_at(tmp_path, LATER + timedelta(hours=1), capsys)
    tail = open_part(out)
    for name in ("cases", "cache", "runs", "evidence"):
        assert f'--{name} "{tmp_path / name}"' in tail.split("WITHOUT A DRAFT")[1]  # the draft command
    approve_line = [l for l in tail.splitlines() if f"cra approve {case_id}" in l][0]
    for name in ("cases", "cache", "evidence"):
        assert f'--{name} "{tmp_path / name}"' in approve_line


def test_no_ready_made_command_is_printed_for_a_path_with_special_characters(tmp_path, capsys):
    from src import case_commands
    case_commands.print_open_cases(tmp_path / "cases", NOW, {"manufacturer": "M GmbH", "product_name": "P"},
                                   [{"component": "c", "version": "1", "exploited_cve": "CVE-2021-44228"}],
                                   tmp_path / "runs" / "a$(calc).json", tmp_path / "s.json", tmp_path / "c.json")
    out = capsys.readouterr().out
    assert "no ready-made command is shown" in out and "$(calc)" not in out


def test_more_than_1000_case_folders_are_reported_not_silently_cut(tmp_path):
    root = tmp_path / "cases"
    root.mkdir()
    for i in range(1001):
        (root / f"case-{i:012x}").mkdir()
    found, unreadable = cases.list_cases(root)
    assert any("NOT read" in item for item in unreadable)


def test_a_network_path_in_case_json_is_never_opened(tmp_path, monkeypatch):
    case_id = make_case(tmp_path)
    approve((tmp_path, case_id), Keyboard(*good_answers(case_id)))
    path = tmp_path / "cases" / case_id / "case.json"
    meta = json.loads(path.read_text(encoding="utf-8"))
    meta["origin"]["sbom"]["path"] = "\\\\attacker\\share\\sbom.json"
    path.write_text(json.dumps(meta), encoding="utf-8")
    from src import sbom_reader

    def must_not_open(*args, **kwargs):
        raise AssertionError("a network path must not be opened")

    monkeypatch.setattr(sbom_reader, "read_sbom_bytes", must_not_open)
    assert cases.approval_state(cases.load_case(tmp_path / "cases", case_id)) == "CHANGED"
    assert cases.is_local_path("C:\\data\\x.json") and not cases.is_local_path("//host/share/x") and not cases.is_local_path("\\\\h\\s")


def test_the_approvals_log_is_read_once_for_many_cases(tmp_path, monkeypatch):
    case_id = make_case(tmp_path)
    approve((tmp_path, case_id), Keyboard(*good_answers(case_id)))
    case = cases.load_case(tmp_path / "cases", case_id)
    reads = []
    real_open = open
    monkeypatch.setattr("builtins.open", lambda f, *a, **k: (reads.append(str(f)), real_open(f, *a, **k))[1])
    for _ in range(5):
        cases.approval_state(case)
    assert len([r for r in reads if r.endswith("approvals.log")]) <= 1


def test_a_failed_run_prints_the_list_of_open_cases_too(tmp_path, capsys):
    make_case(tmp_path)
    capsys.readouterr()

    def broken(*args, **kwargs):
        raise OSError("network down")

    from tests.test_cli_run import CONFIG, SBOM
    code = main(["run", "--sbom", SBOM, "--config", CONFIG, "--cache", str(tmp_path / "cache2"), "--runs", str(tmp_path / "runs"),
                 "--evidence", str(tmp_path / "evidence"), "--cases", str(tmp_path / "cases")],
                fetch=broken, sleep=lambda s: None, now=lambda: LATER)
    out = capsys.readouterr().out
    assert code == 1 and "RESULT INCOMPLETE" in out
    assert "OPEN CASES" in out  # a run with no data must not hide the cases that still have a deadline
