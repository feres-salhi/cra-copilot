"""Tests for the reviewer/auditor findings about `cra run` and `cra status`."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from src import news_watcher as nw
from src.cli import main
from tests.test_cli_run import CONFIG, SBOM, clock, run_cli, saved_run, write_sbom
from tests.test_news_watcher import FakeNet, no_sleep

NOW = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)


def put_run(folder, **overrides):
    run = {
        "finished_at": NOW.isoformat(),
        "complete": True,
        "sources": {"kev": {"status": "ok", "detail": "d"}, "osv": {"status": "ok", "detail": "d"}},
        "components": {"checked": 1, "unchecked": 0},
    }
    run.update(overrides)
    nw.save_run(folder, run, lambda: NOW)


def status(folder, now=clock):
    return nw.status_summary(folder, now)


# ------------------------------------------------------------------ run: storage errors and safety net


def test_unwritable_runs_folder_still_shows_the_report_case_and_exit_3(tmp_path, capsys):
    blocker = tmp_path / "runs"
    blocker.write_text("i am a file, not a folder", encoding="utf-8")  # --runs points at a file
    code = run_cli(tmp_path)
    out = capsys.readouterr().out
    assert code == 3
    assert "REPORT CASE" in out
    assert "RUN NOT SAVED" in out and "RESULT INCOMPLETE" in out
    assert "Traceback" not in out


def test_unusable_cache_folder_gives_incomplete_not_a_traceback(tmp_path, capsys):
    (tmp_path / "cache").write_text("i am a file", encoding="utf-8")
    code = run_cli(tmp_path)
    out = capsys.readouterr().out
    assert code == 1
    assert "RESULT INCOMPLETE" in out and "cache folder could not be used" in out
    assert "Nothing was sent" in out


def test_an_unexpected_internal_error_is_incomplete_not_a_crash(tmp_path, capsys, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("secret path C:\\x\\y")

    monkeypatch.setattr("src.matcher.evaluate", boom)
    code = run_cli(tmp_path)
    out = capsys.readouterr().out
    assert code == 1
    assert "RESULT INCOMPLETE - internal error (RuntimeError)" in out
    assert "secret path" not in out  # the message text (which could hold paths) is not printed


def test_run_file_records_the_complete_flag_and_counts(tmp_path):
    run_cli(tmp_path)
    run = saved_run(tmp_path)
    assert run["complete"] is False  # the demo has an unchecked firmware component
    assert run["report_cases"] == 2 and run["needs_human"] is True
    run_cli(tmp_path / "clean", sbom=write_sbom(tmp_path, ["pkg:pypi/packaging@24.1"]))
    clean = saved_run(tmp_path / "clean")
    assert (clean["complete"], clean["report_cases"], clean["needs_human"]) == (True, 0, False)


def test_stale_kev_is_an_incomplete_run(tmp_path, capsys):
    run_cli(tmp_path, sbom=write_sbom(tmp_path, ["pkg:pypi/packaging@24.1"]))  # saves a good KEV copy
    capsys.readouterr()
    other = tmp_path / "second"
    other.mkdir()
    # same cache, KEV down now
    args = ["run", "--sbom", write_sbom(tmp_path, ["pkg:pypi/packaging@24.1"]), "--config", CONFIG,
            "--cache", str(tmp_path / "cache"), "--runs", str(other / "runs"), "--evidence", str(other / "e")]
    code = main(args, fetch=FakeNet(kev=nw.FetchError("down")), sleep=no_sleep, now=clock)
    out = capsys.readouterr().out
    assert "Source KEV: stale" in out and "RESULT INCOMPLETE" in out
    assert "No exploited vulnerabilities found" not in out
    assert code == 1


def test_a_clean_but_sbom_with_warning_run_is_incomplete(tmp_path, capsys):
    sbom = tmp_path / "nodeps.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [
        {"name": "packaging", "version": "24.1", "purl": "pkg:pypi/packaging@24.1"}]}), encoding="utf-8")
    code = run_cli(tmp_path, sbom=str(sbom))
    out = capsys.readouterr().out
    assert code == 1 and "RESULT INCOMPLETE" in out and "No exploited vulnerabilities found" not in out
    assert saved_run(tmp_path)["complete"] is False


def test_a_complete_run_with_only_recorded_findings_exits_1_not_0(tmp_path, capsys):
    sbom = write_sbom(tmp_path, ["pkg:pypi/requests@2.30.0"])
    code = run_cli(tmp_path, sbom=sbom)
    out = capsys.readouterr().out
    assert code == 1  # affected but not exploited: a human should still look
    assert "Recorded (affected" in out and "RESULT INCOMPLETE" not in out


def test_the_2_17_1_component_really_was_checked(tmp_path):
    run_cli(tmp_path)
    versions = {f["version"] for f in saved_run(tmp_path)["result"]["findings"]}
    assert "2.17.1" in versions  # (OSV lists newer vulnerabilities for it) so the check below is not vacuous
    for f in saved_run(tmp_path)["result"]["findings"]:
        if f["version"] == "2.17.1":
            assert "CVE-2021-44228" not in f["cve_ids"]


# ------------------------------------------------------------------ status: honest and robust


def test_incomplete_run_does_not_count_as_the_last_successful_run(tmp_path):
    put_run(tmp_path, complete=False)
    lines, ok = status(tmp_path)
    assert not ok
    assert "never been a fully successful run" in "\n".join(lines)


def test_a_run_file_without_a_complete_flag_is_not_complete(tmp_path):
    run = {"finished_at": NOW.isoformat(), "sources": {"kev": {"status": "ok"}, "osv": {"status": "ok"}}}
    nw.save_run(tmp_path, run, lambda: NOW)
    assert status(tmp_path)[1] is False


def test_status_warns_about_report_cases_in_the_latest_run(tmp_path):
    put_run(tmp_path, report_cases=2)
    lines, ok = status(tmp_path)
    assert not ok
    assert any("2 REPORT CASE" in line for line in lines)


def test_status_warns_about_findings_that_need_a_human(tmp_path):
    put_run(tmp_path, needs_human=True)
    lines, ok = status(tmp_path)
    assert not ok and any("need a human look" in line for line in lines)


def test_status_warns_when_the_sbom_had_warnings(tmp_path):
    put_run(tmp_path, sbom_warnings=["SBOM has no components: nothing could be checked"])
    lines, ok = status(tmp_path)
    assert not ok and any("SBOM of the latest run had warnings" in line for line in lines)


def test_status_of_a_clean_complete_run_is_ok(tmp_path):
    put_run(tmp_path, report_cases=0, needs_human=False)
    lines, ok = status(tmp_path)
    assert ok and not any("WARNING" in line for line in lines)


def test_the_exit_code_does_not_depend_on_the_word_warning(tmp_path, capsys):
    put_run(tmp_path, report_cases=1)
    assert main(["status", "--runs", str(tmp_path)], now=clock) == 1
    folder = tmp_path / "clean"
    put_run(folder)
    assert main(["status", "--runs", str(folder)], now=clock) == 0


@pytest.mark.parametrize(
    "damage",
    [
        {"sources": [1]},
        {"sources": {"kev": "ok"}},
        {"sources": "text"},
        {"components": "x"},
        {"components": ["a"]},
        {"report_cases": "many"},
        {"sbom_warnings": 5},
    ],
)
def test_damaged_run_files_never_crash_status(tmp_path, damage):
    put_run(tmp_path, **damage)
    lines, ok = status(tmp_path)
    assert isinstance(lines, list)
    assert main(["status", "--runs", str(tmp_path)], now=clock) in (0, 1)


def test_a_damaged_sources_field_counts_as_incomplete(tmp_path):
    put_run(tmp_path, sources={"kev": "ok"})
    assert status(tmp_path)[1] is False


def test_text_from_a_run_file_cannot_clear_the_screen(tmp_path, capsys):
    hostile = "\x1b[2J\x1b]0;pwned\x07FAKE all clear"
    put_run(tmp_path, complete=False, sources={"kev": {"status": hostile, "detail": hostile}})
    main(["status", "--runs", str(tmp_path)], now=clock)
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "FAKE all clear" in out  # the harmless text stays visible, only control characters are replaced


def test_printable_helper():
    assert nw.printable("a\x1bb\nc") == "a?b?c"
    assert nw.printable(5) == "5"
    assert len(nw.printable("x" * 1000)) == 200


def test_a_far_future_run_file_does_not_say_all_sources_ok(tmp_path):
    put_run(tmp_path)  # a normal run now
    nw.save_run(tmp_path, {"finished_at": (NOW + timedelta(days=400)).isoformat(), "complete": True,
                           "sources": {"kev": {"status": "ok"}, "osv": {"status": "ok"}}}, lambda: NOW)
    lines, ok = status(tmp_path)
    assert not ok
    assert "Latest run: all sources ok." not in lines
    assert any("future" in line for line in lines)


def test_only_the_newest_run_files_are_read(tmp_path, monkeypatch):
    monkeypatch.setattr(nw, "MAX_RUN_FILES", 3)
    for i in range(6):
        nw.save_run(tmp_path, {"finished_at": (NOW + timedelta(seconds=i)).isoformat(), "marker": i}, lambda: NOW + timedelta(seconds=i))
    assert [r["marker"] for r in nw.load_runs(tmp_path)] == [3, 4, 5]


# ------------------------------------------------------------------ temp files


def test_atomic_write_leaves_no_temp_files_and_replaces_the_file(tmp_path):
    target = tmp_path / "x.json"
    nw._write_json_atomic(target, {"a": 1})
    nw._write_json_atomic(target, {"a": 2})
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": 2}
    assert [p.name for p in tmp_path.iterdir()] == ["x.json"]


def test_atomic_write_that_fails_cleans_up(tmp_path):
    class NotJson:
        pass

    with pytest.raises(TypeError):
        nw._write_json_atomic(tmp_path / "x.json", {"a": NotJson()})
    assert list(tmp_path.iterdir()) == []
