"""Q1 piece 3: every alert is appended to cache/alerts.log (time in UTC and Berlin time, kind, ids)."""

import re
from datetime import datetime, timedelta, timezone

import pytest

from src import alerts
from tests.test_alerts_rules import FakeNotifier, NOW, run_with

NOW_SUMMER = datetime(2026, 7, 1, 10, 30, tzinfo=timezone.utc)
ITEM = alerts.Item(alerts.NEW_REPORT_CASE, "report:aaaaaaaaaaaa", cve="CVE-2021-44228", case_id="case-0123456789ab")


def log_lines(tmp_path):
    return (tmp_path / "cache" / "alerts.log").read_text(encoding="utf-8").splitlines()


def test_a_line_has_utc_time_berlin_time_kind_and_ids(tmp_path):
    assert alerts.append_log(tmp_path, NOW, alerts.NEW_REPORT_CASE, [ITEM], True) is True
    (line,) = (tmp_path / "alerts.log").read_text(encoding="utf-8").splitlines()
    assert line == ("2026-10-21T12:00:00Z | 2026-10-21 14:00 CEST Berlin | NEW_REPORT_CASE | "
                    "CVE-2021-44228 (case-0123456789ab) | toast: shown")


def test_berlin_time_follows_winter_time(tmp_path):
    alerts.append_log(tmp_path, datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc), alerts.RUN_FAILED, [], False)
    line = (tmp_path / "alerts.log").read_text(encoding="utf-8")
    assert "2026-11-02T12:00:00Z | 2026-11-02 13:00 CET Berlin | RUN_FAILED" in line and "toast: not shown" in line


def test_every_alert_of_a_run_is_in_the_log_even_when_the_toast_works(tmp_path):
    run_with(tmp_path, FakeNotifier())
    lines = log_lines(tmp_path)
    assert len(lines) == 1 and "NEW_REPORT_CASE" in lines[0] and "CVE-2021-44228" in lines[0] and "toast: shown" in lines[0]


def test_lines_are_appended_not_replaced(tmp_path):
    alerts.append_log(tmp_path, NOW, alerts.NEW_REPORT_CASE, [ITEM], True)
    alerts.append_log(tmp_path, NOW + timedelta(hours=1), alerts.RUN_FAILED, [], False)
    assert len((tmp_path / "alerts.log").read_text(encoding="utf-8").splitlines()) == 2


def test_only_validated_values_can_reach_the_log(tmp_path):
    evil = alerts.Item(alerts.NEW_REPORT_CASE, "report:aaaaaaaaaaaa", cve="CVE-2021-1\nFAKE LINE", case_id="case-x; rm")
    alerts.append_log(tmp_path, NOW, alerts.NEW_REPORT_CASE, [evil], True)
    text = (tmp_path / "alerts.log").read_text(encoding="utf-8")
    assert len(text.splitlines()) == 1 and "FAKE" not in text and "case-x" not in text


def test_many_ids_are_shortened(tmp_path):
    items = [alerts.Item(alerts.NEW_REPORT_CASE, f"report:{i:012x}", cve=f"CVE-2021-{10000 + i}") for i in range(60)]
    alerts.append_log(tmp_path, NOW, alerts.NEW_REPORT_CASE, items, True)
    (line,) = (tmp_path / "alerts.log").read_text(encoding="utf-8").splitlines()
    assert "and 40 more" in line and len(line) < 1200


def test_a_log_that_cannot_be_written_gives_false_not_a_crash(tmp_path):
    (tmp_path / "alerts.log").mkdir()
    assert alerts.append_log(tmp_path, NOW, alerts.RUN_FAILED, [], True) is False


def test_the_cache_folder_is_created_if_missing(tmp_path):
    target = tmp_path / "new" / "cache"
    assert alerts.append_log(target, NOW, alerts.RUN_FAILED, [], True) is True
    assert (target / "alerts.log").is_file()


def test_a_big_log_is_moved_aside_so_it_cannot_grow_forever(tmp_path, monkeypatch):
    monkeypatch.setattr(alerts, "MAX_LOG_BYTES", 300)
    for i in range(10):
        alerts.append_log(tmp_path, NOW + timedelta(minutes=i), alerts.RUN_FAILED, [], True)
    assert (tmp_path / "alerts.log.1").is_file()
    assert (tmp_path / "alerts.log").stat().st_size <= 300 + 200
    # the newest line is always in the current file
    assert "2026-10-21T12:09:00Z" in (tmp_path / "alerts.log").read_text(encoding="utf-8")


def test_the_log_is_not_in_the_git_upload_folder():
    from pathlib import Path
    ignore = (Path(__file__).parent.parent / ".gitignore").read_text(encoding="utf-8")
    assert "cache/" in ignore  # alerts.log and alerts-state.json live in cache/


def test_a_failed_rotation_does_not_stop_the_log(tmp_path, monkeypatch):
    monkeypatch.setattr(alerts, "MAX_LOG_BYTES", 50)
    alerts.append_log(tmp_path, NOW, alerts.RUN_FAILED, [], True)
    (tmp_path / "alerts.log.1").mkdir()  # the old-log name is blocked
    assert alerts.append_log(tmp_path, NOW + timedelta(hours=1), alerts.RUN_FAILED, [], True) is True
    assert len((tmp_path / "alerts.log").read_text(encoding="utf-8").splitlines()) == 2


def test_a_half_written_last_line_does_not_swallow_the_next_one(tmp_path):
    (tmp_path / "alerts.log").write_bytes(b"2026-10-21T11:00:00Z | half")
    alerts.append_log(tmp_path, NOW, alerts.RUN_FAILED, [], True)
    lines = (tmp_path / "alerts.log").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and lines[0].endswith("half") and lines[1].startswith("2026-10-21T12:00:00Z")


def test_a_bad_item_makes_the_log_return_false_but_never_raises(tmp_path):
    assert alerts.append_log(tmp_path, "not a time", alerts.RUN_FAILED, [], True) is False


def test_a_failed_source_is_named_in_the_log(tmp_path):
    item = alerts.Item(alerts.SOURCE_PROBLEM, "source:kev:failed", source="KEV", status="failed")
    alerts.append_log(tmp_path, NOW, alerts.SOURCE_PROBLEM, [item], True)
    assert "| KEV (failed) |" in (tmp_path / "alerts.log").read_text(encoding="utf-8")


def test_a_toast_that_raises_still_leaves_the_log_line_and_the_alert_is_remembered(tmp_path):
    notifier = FakeNotifier(shown=RuntimeError("boom"))
    run_with(tmp_path, notifier)
    run_with(tmp_path, notifier, when=NOW + timedelta(hours=4))
    assert len(notifier.calls) == 1
    assert "toast: not shown" in log_lines(tmp_path)[0]


def test_a_log_that_fails_is_reported_even_when_the_toast_worked(tmp_path, capsys):
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / "alerts.log").mkdir()
    run_with(tmp_path, FakeNotifier())
    assert "could not be written" in capsys.readouterr().out
