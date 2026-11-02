"""Improvement 3: `cra status` tracks two things separately.
(a) the last run where every SOURCE was ok (the machine worked) - the 26-hour warning uses this one,
(b) whether the RESULT of the latest run was complete (the demo product never is: the firmware has no purl).
"""
from datetime import datetime, timedelta, timezone

from src import news_watcher as nw

NOW = datetime(2026, 11, 2, 12, 0, 0, tzinfo=timezone.utc)


def now():
    return NOW


def record(hours_ago, statuses=None, complete=False, unchecked=1):
    statuses = statuses or {"kev": "ok", "osv": "ok"}
    return {
        "finished_at": (NOW - timedelta(hours=hours_ago)).isoformat(),
        "complete": complete,
        "sources": {n: {"status": s, "detail": f"{n} is {s}"} for n, s in statuses.items()},
        "components": {"checked": 5, "unchecked": unchecked},
    }


def save(tmp_path, *records):
    for rec in records:
        when = datetime.fromisoformat(rec["finished_at"])
        nw.save_run(tmp_path, rec, lambda w=when: w)


def text(tmp_path):
    return "\n".join(nw.status_report(tmp_path, now))


def test_a_stopped_scheduler_is_noticed_even_though_every_run_is_incomplete(tmp_path):
    save(tmp_path, record(40), record(30))  # all sources ok, result incomplete (UNKNOWN component), nothing newer
    out = text(tmp_path)
    assert "more than 26 hours ago" in out and "Is the scheduler still running?" in out


def test_no_stale_warning_when_a_run_with_all_sources_ok_is_recent_even_if_the_result_is_incomplete(tmp_path):
    save(tmp_path, record(3))
    out = text(tmp_path)
    assert "more than" not in out
    assert "RESULT INCOMPLETE" in out  # still never claimed complete


def test_status_always_shows_both_times(tmp_path):
    save(tmp_path, record(10), record(2, {"kev": "failed", "osv": "ok"}))
    lines = nw.status_report(tmp_path, now)
    assert any(l.startswith("Latest run:") and "2 hours ago" in l for l in lines)
    assert any(l.startswith("Latest run with all sources ok:") and "10 hours ago" in l for l in lines)


def test_the_stale_warning_uses_the_run_with_all_sources_ok_not_the_newest_failed_one(tmp_path):
    save(tmp_path, record(40), record(1, {"kev": "failed", "osv": "ok"}))
    out = text(tmp_path)
    assert "more than 26 hours ago" in out and "kev: failed" in out


def test_when_no_run_ever_had_all_sources_ok_it_says_so(tmp_path):
    save(tmp_path, record(5, {"kev": "failed", "osv": "ok"}))
    out = text(tmp_path)
    assert "no run has ever had all sources ok" in out
    assert "Latest run:" in out


def test_a_crashed_run_record_with_no_sources_never_counts_as_all_sources_ok(tmp_path):
    crashed = {"finished_at": (NOW - timedelta(hours=1)).isoformat(), "complete": False, "error": "OSError", "sources": {}, "components": {}}
    save(tmp_path, record(40), crashed)
    out = text(tmp_path)
    assert "more than 26 hours ago" in out


def test_a_complete_result_is_never_claimed_when_components_were_unknown(tmp_path):
    save(tmp_path, record(1, complete=True, unchecked=2))  # an inconsistent record that says "complete" anyway
    lines, ok = nw.status_summary(tmp_path, now)
    out = "\n".join(lines)
    assert ok is False
    assert "Latest run: all sources ok." not in lines
    assert "UNKNOWN" in out


def test_a_really_complete_run_is_still_reported_clean(tmp_path):
    save(tmp_path, record(1, complete=True, unchecked=0))
    lines, ok = nw.status_summary(tmp_path, now)
    assert "Latest run: all sources ok." in lines and ok is True


def test_a_run_dated_in_the_future_is_not_trusted_for_the_age(tmp_path):
    save(tmp_path, record(-5))
    out = text(tmp_path)
    assert "future" in out and "Do not rely on the age" in out


def test_old_run_files_without_new_fields_still_load(tmp_path):
    save(tmp_path, {"finished_at": (NOW - timedelta(hours=2)).isoformat(), "complete": True,
                    "sources": {"kev": {"status": "ok"}, "osv": {"status": "ok"}}})
    lines, ok = nw.status_summary(tmp_path, now)
    assert ok is True and any("Latest run with all sources ok" in l for l in lines)


def test_a_future_dated_run_cannot_hide_a_stale_scheduler(tmp_path):
    """A wrong clock gives a run a date in the future; it must not replace the real last run with all sources ok."""
    save(tmp_path, record(40), record(-5))
    out = text(tmp_path)
    assert "future" in out
    assert "more than 26 hours ago" in out and "40 hours ago" in out
