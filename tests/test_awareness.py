"""Phase 4 piece 2 (part A): the awareness time a human types, and the check against what the tool itself observed."""

from datetime import date, datetime, timedelta, timezone

import pytest

from src import awareness as aw
from src import news_watcher as nw

NOW = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------- parsing what the human typed


@pytest.mark.parametrize("text, expected", [
    ("2026-11-02 09:30 UTC", datetime(2026, 11, 2, 9, 30, tzinfo=timezone.utc)),
    ("2026-11-02 09:30 Z", datetime(2026, 11, 2, 9, 30, tzinfo=timezone.utc)),
    ("2026-11-02 09:30 +01:00", datetime(2026, 11, 2, 8, 30, tzinfo=timezone.utc)),
    ("2026-11-02 09:30 +14:00", datetime(2026, 11, 1, 19, 30, tzinfo=timezone.utc)),
    ("2026-11-02 09:30 -12:00", datetime(2026, 11, 2, 21, 30, tzinfo=timezone.utc)),
    ("2026-11-02 09:30 -05:00", datetime(2026, 11, 2, 14, 30, tzinfo=timezone.utc)),
    ("2026-11-02 09:30 Berlin", datetime(2026, 11, 2, 8, 30, tzinfo=timezone.utc)),   # winter time, UTC+1
    ("2026-07-01 09:30 Berlin", datetime(2026, 7, 1, 7, 30, tzinfo=timezone.utc)),    # summer time, UTC+2
    ("  2026-11-02 09:30 UTC  ", datetime(2026, 11, 2, 9, 30, tzinfo=timezone.utc)),   # blanks around are fine
])
def test_good_times_become_utc(text, expected):
    assert aw.parse_awareness(text) == expected
    assert aw.parse_awareness(text).utcoffset() == timedelta(0)


@pytest.mark.parametrize("bad", [
    "", "   ", "2026-11-02", "2026-11-02 09:30", "2026-11-02T09:30 UTC", "2026-11-02 09:30:15 UTC",
    "2026-13-02 09:30 UTC", "2026-02-30 09:30 UTC", "2026-11-02 25:30 UTC", "2026-11-02 09:60 UTC",
    "2026-11-02 09:30 CET", "2026-11-02 09:30 Europe/Berlin", "2026-11-02 09:30 +0100", "2026-11-02 09:30 +15:00", "2026-11-02 09:30 +14:30", "2026-11-02 09:30 -12:30", "2026-11-02 09:30 -13:00",
    "2026-11-02 09:30 +01:60", "2026-11-02 09:30 utc", "02.11.2026 09:30 UTC", "2026-11-02  09:30 UTC",
    "2026-11-02 09:30 UTC\n2026-11-03 09:30 UTC", "2026-11-02 09:30 UTC\x00", "x" * 5000, "0000-01-01 00:00 UTC",
    "9999-12-31 23:59 -14:00", "２０２６-11-02 09:30 UTC", None, 5,
])
def test_bad_times_are_refused(bad):
    with pytest.raises(aw.AwarenessError):
        aw.parse_awareness(bad)


def test_berlin_time_in_the_repeated_hour_is_refused_not_guessed():
    # 25 Oct 2026, 02:30 happens twice in Berlin (clock goes back from 03:00 CEST to 02:00 CET)
    with pytest.raises(aw.AwarenessError, match="twice"):
        aw.parse_awareness("2026-10-25 02:30 Berlin")
    # with an explicit offset there is no doubt
    assert aw.parse_awareness("2026-10-25 02:30 +02:00") == datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc)
    assert aw.parse_awareness("2026-10-25 02:30 +01:00") == datetime(2026, 10, 25, 1, 30, tzinfo=timezone.utc)


def test_berlin_time_in_the_skipped_hour_is_refused():
    # 29 Mar 2026, 02:30 does not exist in Berlin (clock jumps from 02:00 CET to 03:00 CEST)
    with pytest.raises(aw.AwarenessError, match="does not exist"):
        aw.parse_awareness("2026-03-29 02:30 Berlin")


def test_the_hour_around_the_change_that_is_fine_is_accepted():
    assert aw.parse_awareness("2026-10-25 01:59 Berlin") == datetime(2026, 10, 24, 23, 59, tzinfo=timezone.utc)
    assert aw.parse_awareness("2026-10-25 03:00 Berlin") == datetime(2026, 10, 25, 2, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------- the check against machine-observed times


def observation(first=None, allowed=datetime(2021, 12, 9, 10, 0, tzinfo=timezone.utc), reason="KEV dateAdded 2021-12-10"):
    return aw.Observation(first_found_at=first, first_found_file="2026-11-02T08-00-00Z.json" if first else None,
                          earliest_allowed=allowed, earliest_reason=reason)


def test_a_normal_time_has_no_problems():
    verdict = aw.check_awareness(NOW - timedelta(hours=1), NOW, observation(first=NOW - timedelta(hours=1)))
    assert verdict.refusals == [] and verdict.warnings == [] and not verdict.needs_reason


def test_the_future_is_refused():
    verdict = aw.check_awareness(NOW + timedelta(minutes=1), NOW, observation())
    assert any("future" in r for r in verdict.refusals)


def test_exactly_now_is_allowed():
    assert aw.check_awareness(NOW, NOW, observation()).refusals == []


def test_earlier_than_the_data_allowed_is_refused():
    verdict = aw.check_awareness(datetime(2021, 12, 9, 9, 59, tzinfo=timezone.utc), NOW, observation())
    assert any("earlier" in r and "KEV dateAdded 2021-12-10" in r for r in verdict.refusals)


def test_exactly_the_earliest_allowed_time_is_accepted():
    assert aw.check_awareness(datetime(2021, 12, 9, 10, 0, tzinfo=timezone.utc), NOW, observation()).refusals == []


def test_later_than_the_first_run_is_a_loud_warning_and_needs_a_reason():
    first = NOW - timedelta(hours=10)
    verdict = aw.check_awareness(NOW - timedelta(hours=3), NOW, observation(first=first))
    assert verdict.refusals == []
    assert verdict.needs_reason
    text = " ".join(verdict.warnings)
    assert "LATER than the first run" in text and "7 hours" in text and "2026-11-02T08-00-00Z.json" in text


def test_exactly_at_the_first_run_is_not_a_warning():
    first = NOW - timedelta(hours=10)
    verdict = aw.check_awareness(first, NOW, observation(first=first))
    assert not verdict.needs_reason and verdict.warnings == []


def test_a_passed_deadline_is_a_loud_warning_but_allowed():
    verdict = aw.check_awareness(NOW - timedelta(hours=30), NOW, observation(first=NOW - timedelta(hours=30)))
    assert verdict.refusals == []
    assert any("ALREADY PASSED" in w for w in verdict.warnings)


def test_an_unknown_first_run_is_said_not_hidden():
    verdict = aw.check_awareness(NOW - timedelta(hours=1), NOW, observation(first=None))
    assert any("No sealed run record" in w for w in verdict.warnings)
    assert not verdict.needs_reason


def test_a_naive_time_is_refused_by_the_check():
    with pytest.raises(aw.AwarenessError):
        aw.check_awareness(datetime(2026, 11, 2, 9, 0), NOW, observation())


# ---------------------------------------------------------------- what the data allows


KEV = {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}


def test_earliest_allowed_for_kev_is_the_start_of_the_date_added():
    when, why = aw.earliest_allowed("kev", "CVE-2021-44228", KEV, None)
    assert when == datetime(2021, 12, 9, 10, 0, tzinfo=timezone.utc) and "2021-12-10" in why  # 00:00 at UTC+14


def test_earliest_allowed_for_human_evidence_is_the_evidence_date():
    when, why = aw.earliest_allowed("evidence_file", "CVE-2021-44228", None, "2026-10-30")
    assert when == datetime(2026, 10, 29, 10, 0, tzinfo=timezone.utc) and "2026-10-30" in why


def test_earliest_allowed_refuses_a_cve_that_the_saved_kev_list_does_not_have():
    with pytest.raises(aw.AwarenessError):
        aw.earliest_allowed("kev", "CVE-2020-0001", KEV, None)
    with pytest.raises(aw.AwarenessError):
        aw.earliest_allowed("kev", "CVE-2021-44228", None, None)
    with pytest.raises(aw.AwarenessError):
        aw.earliest_allowed("evidence_file", "CVE-2021-44228", None, "not a date")
    with pytest.raises(aw.AwarenessError):
        aw.earliest_allowed("magic", "CVE-2021-44228", KEV, None)


# ---------------------------------------------------------------- the first run that found the case


def run_record(started, cases, product="SmartHeat X1"):
    findings = [{"action": "REPORT_CASE", "component": c, "version": v, "exploited_cve": cve} for c, v, cve in cases]
    findings.append({"action": "RECORD", "component": "other", "version": "1", "exploited_cve": None})
    return {"started_at": started.isoformat(), "product": {"product_name": product},
            "result": {"findings": findings}, "complete": True, "sources": {}}


KEY = ("SmartHeat X1", "log4j-core", "2.14.1", "CVE-2021-44228")


def test_first_found_is_the_oldest_sealed_run_with_the_same_case(tmp_path):
    runs = tmp_path / "runs"
    t1 = datetime(2026, 11, 1, 6, 0, tzinfo=timezone.utc)
    nw.save_run(runs, run_record(t1 - timedelta(hours=8), []), lambda: t1 - timedelta(hours=8))          # no case yet
    nw.save_run(runs, run_record(t1, [("log4j-core", "2.14.1", "CVE-2021-44228")]), lambda: t1)           # first sight
    t2 = t1 + timedelta(hours=4)
    nw.save_run(runs, run_record(t2, [("log4j-core", "2.14.1", "CVE-2021-44228")]), lambda: t2)
    found = aw.find_first_found(runs, *KEY)
    assert found == (t1, "2026-11-01T06-00-00Z.json")


def test_first_found_ignores_other_products_versions_cves_and_unsealed_runs(tmp_path):
    runs = tmp_path / "runs"
    t = datetime(2026, 11, 1, 6, 0, tzinfo=timezone.utc)
    nw.save_run(runs, run_record(t, [("log4j-core", "2.14.1", "CVE-2021-44228")], product="Other Product"), lambda: t)
    nw.save_run(runs, run_record(t + timedelta(hours=1), [("log4j-core", "2.15.0", "CVE-2021-44228")]), lambda: t + timedelta(hours=1))
    nw.save_run(runs, run_record(t + timedelta(hours=2), [("log4j-core", "2.14.1", "CVE-2021-45046")]), lambda: t + timedelta(hours=2))
    forged = run_record(t - timedelta(days=5), [("log4j-core", "2.14.1", "CVE-2021-44228")])  # not sealed
    (runs / "2026-10-27T06-00-00Z.json").write_text(__import__("json").dumps(forged), encoding="utf-8")
    (runs / "2026-10-28T06-00-00Z.json").write_text("{broken", encoding="utf-8")
    assert aw.find_first_found(runs, *KEY) is None


def test_first_found_with_a_missing_runs_folder_is_none(tmp_path):
    assert aw.find_first_found(tmp_path / "nothing", *KEY) is None


def test_the_run_used_for_drafting_counts_even_when_it_lies_outside_the_runs_folder(tmp_path):
    t = datetime(2026, 11, 1, 6, 0, tzinfo=timezone.utc)
    other = tmp_path / "elsewhere"
    path = nw.save_run(other, run_record(t, [("log4j-core", "2.14.1", "CVE-2021-44228")]), lambda: t)
    found = aw.find_first_found(tmp_path / "runs", *KEY, extra_run_files=[path])
    assert found == (t, path.name)


def test_first_found_stops_at_the_file_limit(tmp_path, monkeypatch):
    runs = tmp_path / "runs"
    runs.mkdir()
    for i in range(5):
        (runs / f"2026-11-0{i + 1}T00-00-00Z.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(aw, "MAX_RUN_FILES", 2)
    seen = []
    real = nw.read_sealed_run
    monkeypatch.setattr(nw, "read_sealed_run", lambda p: (seen.append(p), real(p))[1])
    aw.find_first_found(runs, *KEY)
    assert len(seen) == 2


# ---------------------------------------------------------------- improvement 4: ISO 8601 with "T" and an offset or "Z"


@pytest.mark.parametrize("text, expected", [
    ("2026-11-02T01:50+01:00", datetime(2026, 11, 2, 0, 50, tzinfo=timezone.utc)),   # the time Fares typed
    ("2026-11-02T01:50Z", datetime(2026, 11, 2, 1, 50, tzinfo=timezone.utc)),
    ("2026-11-02T09:30-05:00", datetime(2026, 11, 2, 14, 30, tzinfo=timezone.utc)),
    ("2026-11-02T09:30+14:00", datetime(2026, 11, 1, 19, 30, tzinfo=timezone.utc)),
    ("2026-11-02T09:30+00:00", datetime(2026, 11, 2, 9, 30, tzinfo=timezone.utc)),
    ("  2026-11-02T09:30Z  ", datetime(2026, 11, 2, 9, 30, tzinfo=timezone.utc)),
])
def test_iso_8601_times_become_utc(text, expected):
    assert aw.parse_awareness(text) == expected
    assert aw.parse_awareness(text).utcoffset() == timedelta(0)


@pytest.mark.parametrize("bad", [
    "2026-11-02T01:50",            # no time zone
    "2026-11-02T01:50:00",         # no time zone (with seconds)
    "2026-11-02T01:50:00+01:00",   # seconds are not accepted
    "2026-11-02T01:50:00Z",
    "2026-11-02t01:50Z", "2026-11-02T01:50z",   # lower case
    "2026-11-02T01:50 +01:00", "2026-11-02T01:50 Z",   # a blank before the zone (use the other format)
    "2026-11-02 01:50+01:00",      # a blank instead of T with a glued zone
    "2026-11-02T01:50+0100", "2026-11-02T01:50+01",
    "2026-11-02T01:50+15:00", "2026-11-02T01:50-13:00", "2026-11-02T01:50+01:60",
    "2026-11-02T25:50Z", "2026-02-30T01:50Z", "2026-11-02T01:50Z\n2026-11-03T01:50Z",
    "2026-11-02T01:50.5Z", "2026-11-02T01:50UTC", "2026-11-02T01:50 Berlin",
    "２０２６-11-02T01:50Z",
])
def test_bad_iso_times_are_refused(bad):
    with pytest.raises(aw.AwarenessError):
        aw.parse_awareness(bad)


def test_an_iso_time_goes_through_the_same_future_and_earliest_checks():
    future = aw.parse_awareness("2026-11-02T12:01Z")
    assert any("future" in r for r in aw.check_awareness(future, NOW, observation()).refusals)
    early = aw.parse_awareness("2021-12-09T09:59Z")
    assert any("earlier" in r for r in aw.check_awareness(early, NOW, observation()).refusals)
    fine = aw.parse_awareness("2026-11-02T12:00+00:00")
    assert aw.check_awareness(fine, NOW, observation()).refusals == []


def test_the_help_text_mentions_the_iso_form():
    assert "2026-11-02T01:50+01:00" in aw.FORMAT_HELP
