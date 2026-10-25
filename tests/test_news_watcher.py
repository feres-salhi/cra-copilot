"""Tests for src/news_watcher.py. No test here touches the internet.

A fake network serves the REAL saved copies in tests/fixtures/ (OSV and CISA KEV).
"""

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src import news_watcher as nw
from src.news_watcher import FetchError
from src.sbom_reader import Component

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)

LOG4J_2141 = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
LOG4J_2171 = "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
REQUESTS = "pkg:pypi/requests@2.30.0"
PACKAGING = "pkg:pypi/packaging@24.1"


def _load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


REAL_KEV_BYTES = (FIXTURES / "kev.json").read_bytes()
REAL_KEV = json.loads(REAL_KEV_BYTES)
_BATCH_QUERIES = [
    LOG4J_2141, LOG4J_2171, REQUESTS, PACKAGING,
    "pkg:maven/org.apache.logging.log4j/log4j-core@2.0-beta9",
    "pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0",
]
REAL_BATCH = dict(zip(_BATCH_QUERIES, _load("osv_querybatch_demo.json")["results"]))


class FakeNet:
    """A pretend internet. Counts calls and can be told to fail."""

    def __init__(self, kev=REAL_KEV_BYTES):
        self.kev = kev  # bytes, or a FetchError to raise
        self.batch = dict(REAL_BATCH)  # purl -> OSV result dict
        self.batch_error = None  # FetchError raised for every batch call
        self.vuln_errors = {}  # id -> FetchError
        self.vuln_overrides = {}  # id -> bytes
        self.calls = []
        self.vuln_calls = 0

    def __call__(self, url, body=None, max_bytes=0):
        self.calls.append(url)
        if url == nw.KEV_URL:
            if isinstance(self.kev, Exception):
                raise self.kev
            return self.kev
        if url == nw.OSV_BATCH_URL:
            if self.batch_error:
                raise self.batch_error
            queries = json.loads(body)["queries"]
            return json.dumps({"results": [self.batch.get(q["package"]["purl"], {}) for q in queries]}).encode()
        if url.startswith(nw.OSV_VULN_URL):
            vuln_id = url[len(nw.OSV_VULN_URL):]
            self.vuln_calls += 1
            if vuln_id in self.vuln_errors:
                raise self.vuln_errors[vuln_id]
            if vuln_id in self.vuln_overrides:
                return self.vuln_overrides[vuln_id]
            return (FIXTURES / "osv" / f"{vuln_id}.json").read_bytes()
        raise AssertionError(f"unexpected url {url}")


def no_sleep(seconds):
    no_sleep.slept.append(seconds)


no_sleep.slept = []


@pytest.fixture(autouse=True)
def _reset_sleep():
    no_sleep.slept.clear()


def now():
    return NOW


def component(purl, name="x", version="1"):
    return Component(name, version, purl, "maven", "OK")


# ------------------------------------------------------------------ KEV


def test_kev_download_is_validated_saved_and_fingerprinted(tmp_path):
    data, status = nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
    assert status["status"] == "ok"
    assert status["sha256"] == hashlib.sha256(REAL_KEV_BYTES).hexdigest()
    assert status["downloaded_at"] == NOW.isoformat()
    assert len(data["vulnerabilities"]) == REAL_KEV["count"]
    saved = json.loads((tmp_path / "kev" / "kev-saved.json").read_text(encoding="utf-8"))
    assert saved["sha256"] == status["sha256"] and saved["data"]["count"] == REAL_KEV["count"]


def test_real_kev_copy_contains_log4shell_added_2021_12_10():
    entry = [v for v in REAL_KEV["vulnerabilities"] if v["cveID"] == "CVE-2021-44228"][0]
    assert entry["dateAdded"] == "2021-12-10"


def test_kev_retries_on_429_then_succeeds(tmp_path):
    net = FakeNet()
    answers = [FetchError("HTTP 429", 429), FetchError("HTTP 429", 429)]

    def flaky(url, body=None, max_bytes=0):
        if url == nw.KEV_URL and answers:
            raise answers.pop(0)
        return net(url, body, max_bytes)

    _, status = nw.fetch_kev(tmp_path, flaky, no_sleep, now)
    assert status["status"] == "ok"
    assert no_sleep.slept == [1, 2]


def test_kev_gives_up_after_the_retries_and_has_no_saved_copy_means_failed(tmp_path):
    net = FakeNet(kev=FetchError("HTTP 429", 429))
    data, status = nw.fetch_kev(tmp_path, net, no_sleep, now)
    assert data is None
    assert status["status"] == "failed"
    assert net.calls.count(nw.KEV_URL) == nw.RETRIES + 1


def test_kev_does_not_retry_a_404(tmp_path):
    net = FakeNet(kev=FetchError("HTTP 404", 404))
    nw.fetch_kev(tmp_path, net, no_sleep, now)
    assert net.calls.count(nw.KEV_URL) == 1


def test_kev_failure_with_saved_copy_is_stale_not_ok(tmp_path):
    nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)  # saves a good copy
    data, status = nw.fetch_kev(tmp_path, FakeNet(kev=FetchError("down")), no_sleep, now)
    assert status["status"] == "stale"
    assert len(data["vulnerabilities"]) == REAL_KEV["count"]


def test_kev_cut_off_download_is_stale(tmp_path):
    nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
    _, status = nw.fetch_kev(tmp_path, FakeNet(kev=REAL_KEV_BYTES[:5000]), no_sleep, now)
    assert status["status"] == "stale"


@pytest.mark.parametrize("missing", ["catalogVersion", "dateReleased", "count", "vulnerabilities"])
def test_kev_missing_required_field_is_rejected(tmp_path, missing):
    broken = copy.deepcopy(REAL_KEV)
    del broken[missing]
    assert "missing the field" in nw.validate_kev(broken)


def test_kev_count_must_equal_real_number_of_entries():
    broken = copy.deepcopy(REAL_KEV)
    broken["count"] += 1
    assert "does not match" in nw.validate_kev(broken)


def test_kev_drop_of_more_than_5_percent_is_rejected_and_old_copy_kept(tmp_path):
    nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
    smaller = copy.deepcopy(REAL_KEV)
    smaller["vulnerabilities"] = smaller["vulnerabilities"][: int(REAL_KEV["count"] * 0.9)]
    smaller["count"] = len(smaller["vulnerabilities"])
    data, status = nw.fetch_kev(tmp_path, FakeNet(kev=json.dumps(smaller).encode()), no_sleep, now)
    assert status["status"] == "stale"
    assert "5%" in status["detail"]
    assert len(data["vulnerabilities"]) == REAL_KEV["count"]  # old copy kept


def test_kev_drop_of_less_than_5_percent_is_no_longer_accepted(tmp_path):
    # Before vuln-0007 a small drop was accepted. Now ANY dropped id makes KEV stale (a human checks).
    nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
    smaller = copy.deepcopy(REAL_KEV)
    smaller["vulnerabilities"] = smaller["vulnerabilities"][: int(REAL_KEV["count"] * 0.97)]
    smaller["count"] = len(smaller["vulnerabilities"])
    _, status = nw.fetch_kev(tmp_path, FakeNet(kev=json.dumps(smaller).encode()), no_sleep, now)
    assert status["status"] == "stale"


@pytest.mark.parametrize("field,value", [("cveID", "../../etc"), ("cveID", 5), ("dateAdded", "yesterday")])
def test_kev_entry_with_a_bad_field_is_rejected(field, value):
    broken = copy.deepcopy(REAL_KEV)
    broken["vulnerabilities"][0][field] = value
    assert nw.validate_kev(broken)


def test_kev_empty_list_is_rejected():
    assert nw.validate_kev({"catalogVersion": "1", "dateReleased": "x", "count": 0, "vulnerabilities": []})


def test_damaged_saved_kev_copy_is_ignored(tmp_path):
    kev_dir = tmp_path / "kev"
    kev_dir.mkdir()
    (kev_dir / "kev-saved.json").write_text('{"data": {"count": 1}}', encoding="utf-8")
    assert nw.load_kev_cache(tmp_path) == (None, None)


def test_kev_ids_helper():
    assert "CVE-2021-44228" in nw.kev_cve_ids(REAL_KEV)
    assert nw.kev_cve_ids(None) == set()


# ------------------------------------------------------------------ network safety


@pytest.mark.parametrize(
    "url",
    ["http://api.osv.dev/v1/querybatch", "https://evil.example/x", "ftp://api.osv.dev/x",
     "https://api.osv.dev.evil.example/x", "file:///c:/windows/win.ini"],
)
def test_http_fetch_refuses_other_addresses_without_connecting(url):
    with pytest.raises(FetchError, match="allowed list"):
        nw.http_fetch(url)


def test_redirects_are_refused():
    handler = nw._NoRedirects()
    with pytest.raises(FetchError, match="redirect"):
        handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example/")


# ------------------------------------------------------------------ OSV


def test_osv_real_answers_for_the_demo_components(tmp_path):
    purls = [LOG4J_2141, LOG4J_2171, REQUESTS, PACKAGING]
    purl_vulns, vulns, status = nw.fetch_osv(purls, tmp_path, FakeNet(), no_sleep, now)
    assert status["status"] == "ok"
    assert "GHSA-jfh8-c2jp-5v3q" in purl_vulns[LOG4J_2141]  # Log4Shell
    assert "GHSA-jfh8-c2jp-5v3q" not in purl_vulns[LOG4J_2171]
    assert purl_vulns[PACKAGING] == []
    assert "GHSA-j8r2-6x86-q33q" in purl_vulns[REQUESTS]
    assert vulns["GHSA-jfh8-c2jp-5v3q"]["aliases"] == ["CVE-2021-44228"]


def test_osv_uses_only_purls_in_the_request(tmp_path):
    net = FakeNet()
    nw.fetch_osv([PACKAGING], tmp_path, net, no_sleep, now)
    assert net.calls == [nw.OSV_BATCH_URL]  # no details needed when nothing is listed


def test_osv_following_result_pages(tmp_path):
    net = FakeNet()
    pages = {
        None: {"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q", "modified": "m"}], "next_page_token": "T1"},
        "T1": {"vulns": [{"id": "GHSA-7rjr-3q55-vv33", "modified": "m"}]},
    }

    def paged(url, body=None, max_bytes=0):
        if url == nw.OSV_BATCH_URL:
            query = json.loads(body)["queries"][0]
            return json.dumps({"results": [pages[query.get("page_token")]]}).encode()
        return net(url, body, max_bytes)

    purl_vulns, _, status = nw.fetch_osv([LOG4J_2141], tmp_path, paged, no_sleep, now)
    assert purl_vulns[LOG4J_2141] == ["GHSA-7rjr-3q55-vv33", "GHSA-jfh8-c2jp-5v3q"]
    assert status["status"] == "ok"


def test_osv_page_loop_that_never_ends_gives_no_answer(tmp_path):
    endless = {"vulns": [], "next_page_token": "again"}

    def paged(url, body=None, max_bytes=0):
        return json.dumps({"results": [endless]}).encode()

    purl_vulns, _, status = nw.fetch_osv([LOG4J_2141], tmp_path, paged, no_sleep, now)
    assert purl_vulns[LOG4J_2141] is None
    assert status["status"] == "failed"


def test_osv_429_forever_means_unknown_and_failed_never_empty(tmp_path):
    net = FakeNet()
    net.batch_error = FetchError("HTTP 429", 429)
    purl_vulns, vulns, status = nw.fetch_osv([LOG4J_2141], tmp_path, net, no_sleep, now)
    assert purl_vulns[LOG4J_2141] is None  # None = no answer, NOT an empty list
    assert status["status"] == "failed"
    assert net.calls.count(nw.OSV_BATCH_URL) == nw.RETRIES + 1


def test_osv_failure_with_saved_answer_is_stale_and_uses_it(tmp_path):
    nw.fetch_osv([LOG4J_2141], tmp_path, FakeNet(), no_sleep, now)  # saves answers
    net = FakeNet()
    net.batch_error = FetchError("down")
    purl_vulns, vulns, status = nw.fetch_osv([LOG4J_2141], tmp_path, net, no_sleep, now)
    assert status["status"] == "stale"
    assert "GHSA-jfh8-c2jp-5v3q" in purl_vulns[LOG4J_2141]
    assert vulns["GHSA-jfh8-c2jp-5v3q"] is not None


def test_osv_wrong_number_of_results_is_no_answer(tmp_path):
    def bad(url, body=None, max_bytes=0):
        return json.dumps({"results": []}).encode()

    purl_vulns, _, status = nw.fetch_osv([LOG4J_2141], tmp_path, bad, no_sleep, now)
    assert purl_vulns[LOG4J_2141] is None and status["status"] == "failed"


@pytest.mark.parametrize("evil_id", ["../../secret", "a/b", "", "x" * 100, 5])
def test_osv_invalid_vulnerability_id_is_rejected(tmp_path, evil_id):
    net = FakeNet()
    net.batch[LOG4J_2141] = {"vulns": [{"id": evil_id, "modified": "m"}]}
    purl_vulns, vulns, status = nw.fetch_osv([LOG4J_2141], tmp_path, net, no_sleep, now)
    assert purl_vulns[LOG4J_2141] is None
    assert status["status"] == "failed"
    assert not any(tmp_path.rglob("secret*"))


def test_vulnerability_id_is_checked_before_a_path_is_built(tmp_path):
    with pytest.raises(ValueError):
        nw._vuln_cache_path(tmp_path, "../x")


def test_osv_detail_failure_without_saved_copy_gives_none_and_failed(tmp_path):
    net = FakeNet()
    net.vuln_errors["GHSA-jfh8-c2jp-5v3q"] = FetchError("HTTP 500", 500)
    purl_vulns, vulns, status = nw.fetch_osv([LOG4J_2141], tmp_path, net, no_sleep, now)
    assert vulns["GHSA-jfh8-c2jp-5v3q"] is None
    assert status["status"] == "failed"


def test_osv_detail_failure_with_saved_copy_is_stale(tmp_path):
    nw.fetch_osv([LOG4J_2141], tmp_path, FakeNet(), no_sleep, now)
    # OSV now says the record changed, but the details download fails.
    net = FakeNet()
    net.batch[LOG4J_2141] = copy.deepcopy(REAL_BATCH[LOG4J_2141])
    for item in net.batch[LOG4J_2141]["vulns"]:
        item["modified"] = "2099-01-01T00:00:00Z"
    net.vuln_errors = {item["id"]: FetchError("down") for item in net.batch[LOG4J_2141]["vulns"]}
    _, vulns, status = nw.fetch_osv([LOG4J_2141], tmp_path, net, no_sleep, now)
    assert status["status"] == "stale"
    assert all(v is not None for v in vulns.values())


def test_osv_unchanged_records_are_not_downloaded_again(tmp_path):
    first = FakeNet()
    nw.fetch_osv([LOG4J_2141], tmp_path, first, no_sleep, now)
    assert first.vuln_calls > 0
    second = FakeNet()
    _, _, status = nw.fetch_osv([LOG4J_2141], tmp_path, second, no_sleep, now)
    assert second.vuln_calls == 0
    assert status["status"] == "ok"


def test_osv_record_with_the_wrong_id_is_rejected(tmp_path):
    net = FakeNet()
    net.vuln_overrides["GHSA-jfh8-c2jp-5v3q"] = (FIXTURES / "osv" / "GHSA-7rjr-3q55-vv33.json").read_bytes()
    _, vulns, status = nw.fetch_osv([LOG4J_2141], tmp_path, net, no_sleep, now)
    assert vulns["GHSA-jfh8-c2jp-5v3q"] is None
    assert status["status"] == "failed"


def test_osv_duplicate_purls_are_asked_once(tmp_path):
    net = FakeNet()
    nw.fetch_osv([PACKAGING, PACKAGING], tmp_path, net, no_sleep, now)
    assert net.calls.count(nw.OSV_BATCH_URL) == 1


# ------------------------------------------------------------------ collect + runs


def test_collect_asks_only_about_ok_components(tmp_path):
    comps = [component(PACKAGING), Component("fw", "3", None, None, "UNKNOWN", "no purl")]
    feeds = nw.collect(comps, tmp_path, FakeNet(), no_sleep, now)
    assert feeds.sources_ok
    assert (feeds.checked, feeds.unchecked) == (1, 1)
    assert not feeds.complete  # one component was never checked, so it can NOT be called complete
    assert list(feeds.purl_vulns) == [PACKAGING]


def test_collect_is_complete_only_when_everything_was_checked_and_every_source_ok(tmp_path):
    feeds = nw.collect([component(PACKAGING)], tmp_path, FakeNet(), no_sleep, now)
    assert feeds.complete


def test_collect_with_no_checkable_component_is_never_complete(tmp_path):
    feeds = nw.collect([Component("fw", "3", None, None, "UNKNOWN", "no purl")], tmp_path, FakeNet(), no_sleep, now)
    assert not feeds.complete and feeds.checked == 0 and feeds.unchecked == 1
    assert feeds.osv_status["purls_asked"] == 0


def test_collect_is_not_complete_when_any_source_is_not_ok(tmp_path):
    feeds = nw.collect([component(PACKAGING)], tmp_path, FakeNet(kev=FetchError("down")), no_sleep, now)
    assert not feeds.complete
    assert feeds.kev_status["status"] == "failed"


def _run(finished, statuses):
    return {
        "finished_at": finished.isoformat(),
        "complete": all(s == "ok" for s in statuses.values()),
        "sources": {name: {"status": s, "detail": f"{name} is {s}"} for name, s in statuses.items()},
    }


def test_save_run_does_not_overwrite_a_run_from_the_same_second(tmp_path):
    first = nw.save_run(tmp_path, _run(NOW, {"kev": "ok"}), now)
    second = nw.save_run(tmp_path, _run(NOW, {"kev": "ok"}), now)
    assert first != second and first.exists() and second.exists()
    assert ":" not in first.name  # safe file name on Windows


def test_status_without_any_run_warns(tmp_path):
    assert "no run found" in nw.status_report(tmp_path, now)[0]


def test_status_recent_complete_run_has_no_warning(tmp_path):
    nw.save_run(tmp_path, _run(NOW - timedelta(hours=2), {"kev": "ok", "osv": "ok"}), now)
    lines = nw.status_report(tmp_path, now)
    assert "2 hours ago" in lines[0]
    assert not any("WARNING" in line for line in lines)


def test_status_warns_loudly_after_26_hours(tmp_path):
    nw.save_run(tmp_path, _run(NOW - timedelta(hours=27), {"kev": "ok", "osv": "ok"}), now)
    assert any("more than 26 hours ago" in line for line in nw.status_report(tmp_path, now))


def test_status_exactly_26_hours_is_not_yet_a_warning(tmp_path):
    nw.save_run(tmp_path, _run(NOW - timedelta(hours=26), {"kev": "ok", "osv": "ok"}), now)
    assert not any("more than" in line for line in nw.status_report(tmp_path, now))


def test_status_shows_result_incomplete_when_the_latest_run_is_not_ok(tmp_path):
    nw.save_run(tmp_path, _run(NOW - timedelta(hours=30), {"kev": "ok", "osv": "ok"}), lambda: NOW - timedelta(hours=30))
    nw.save_run(tmp_path, _run(NOW - timedelta(hours=1), {"kev": "stale", "osv": "ok"}), now)
    text = "\n".join(nw.status_report(tmp_path, now))
    assert "RESULT INCOMPLETE" in text
    assert "kev: stale" in text


def test_status_when_no_run_was_ever_successful(tmp_path):
    nw.save_run(tmp_path, _run(NOW, {"kev": "failed", "osv": "ok"}), now)
    text = "\n".join(nw.status_report(tmp_path, now))
    assert "never been a fully successful run" in text
    assert "RESULT INCOMPLETE" in text


def test_a_damaged_run_file_is_never_ignored(tmp_path):
    # vuln-0013: a damaged file stands in as an INCOMPLETE run instead of vanishing.
    (tmp_path / "2026-01-01T00-00-00Z.json").write_text("{ nope", encoding="utf-8")
    lines, ok = nw.status_summary(tmp_path, now)
    assert ok is False
    assert "RESULT INCOMPLETE" in "\n".join(lines)


def test_modified_times_with_6_and_9_decimals_count_as_the_same():
    assert nw.same_modified_time("2026-09-10T03:50:42.492278Z", "2026-09-10T03:50:42.492278990Z")
    assert nw.same_modified_time("2025-09-02T22:25:25Z", "2025-09-02T22:25:25.000000000Z")


def test_different_or_odd_modified_times_do_not_match():
    assert not nw.same_modified_time("2026-09-10T03:50:42.492278Z", "2026-09-10T03:50:42.492279Z")
    assert not nw.same_modified_time("2026-09-10T03:50:42Z", "2026-09-10T03:50:43Z")
    assert not nw.same_modified_time(None, "2026-09-10T03:50:42Z")
    assert not nw.same_modified_time("not a time", "not a time")


# ------------------------------------------------------------------ second review round (reviewer + auditor findings)


def test_kev_date_released_must_be_a_real_time():
    broken = copy.deepcopy(REAL_KEV)
    broken["dateReleased"] = "x"
    assert "dateReleased" in nw.validate_kev(broken)
    broken["dateReleased"] = "2026-10-20T19:00:31"  # no time zone
    assert "dateReleased" in nw.validate_kev(broken)


def test_kev_date_added_must_be_a_real_calendar_date():
    broken = copy.deepcopy(REAL_KEV)
    broken["vulnerabilities"][0]["dateAdded"] = "2021-13-45"
    assert "dateAdded" in nw.validate_kev(broken)


def test_kev_duplicate_cve_ids_are_rejected():
    broken = copy.deepcopy(REAL_KEV)
    broken["vulnerabilities"][1]["cveID"] = broken["vulnerabilities"][0]["cveID"]
    assert "twice" in nw.validate_kev(broken)


def test_kev_older_catalog_than_the_saved_copy_is_rejected_as_a_replay(tmp_path):
    nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
    older = copy.deepcopy(REAL_KEV)
    older["dateReleased"] = "2020-01-01T00:00:00Z"
    data, status = nw.fetch_kev(tmp_path, FakeNet(kev=json.dumps(older).encode()), no_sleep, now)
    assert status["status"] == "stale" and "replay" in status["detail"]


def test_kev_slow_shrinking_is_caught_against_the_highest_count_seen(tmp_path):
    nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)  # highest count = full list
    step = copy.deepcopy(REAL_KEV)
    for fraction in (0.97, 0.94):  # each step is under 5% from the previous one, 6% from the start
        step["vulnerabilities"] = REAL_KEV["vulnerabilities"][: int(REAL_KEV["count"] * fraction)]
        step["count"] = len(step["vulnerabilities"])
        _, status = nw.fetch_kev(tmp_path, FakeNet(kev=json.dumps(step).encode()), no_sleep, now)
    assert status["status"] == "stale"


def test_a_cut_off_json_answer_is_retried(tmp_path):
    answers = [REAL_KEV_BYTES[:1000], REAL_KEV_BYTES[:50]]

    def flaky(url, body=None, max_bytes=0):
        return answers.pop(0) if answers else REAL_KEV_BYTES

    _, status = nw.fetch_kev(tmp_path, flaky, no_sleep, now)
    assert status["status"] == "ok"
    assert no_sleep.slept == [1, 2]


class _FakeResponse:
    def __init__(self, body, length=None):
        self._chunks = [body[i:i + 10] for i in range(0, len(body), 10)] + [b""]
        self.headers = {} if length is None else {"Content-Length": str(length)}

    def read(self, size=-1):
        return self._chunks.pop(0) if self._chunks else b""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeOpener:
    def __init__(self, response=None, error=None):
        self.response, self.error = response, error

    def open(self, request, timeout=None):
        if self.error:
            raise self.error
        return self.response


def _patch_opener(monkeypatch, **kwargs):
    monkeypatch.setattr(nw.urllib.request, "build_opener", lambda *handlers: _FakeOpener(**kwargs))


def test_http_fetch_returns_the_body_of_a_normal_answer(monkeypatch):
    _patch_opener(monkeypatch, response=_FakeResponse(b"hello world, 25 bytes long", length=26))
    assert nw.http_fetch(nw.OSV_BATCH_URL) == b"hello world, 25 bytes long"


def test_http_fetch_answer_shorter_than_content_length_is_a_failure(monkeypatch):
    _patch_opener(monkeypatch, response=_FakeResponse(b"cut off", length=5000))
    with pytest.raises(FetchError, match="cut off"):
        nw.http_fetch(nw.OSV_BATCH_URL)


def test_http_fetch_turns_incomplete_read_into_a_fetch_error(monkeypatch):
    import http.client

    _patch_opener(monkeypatch, error=http.client.IncompleteRead(b"abc"))
    with pytest.raises(FetchError):
        nw.http_fetch(nw.OSV_BATCH_URL)


def test_http_fetch_size_cap(monkeypatch):
    _patch_opener(monkeypatch, response=_FakeResponse(b"x" * 100))
    with pytest.raises(FetchError, match="size cap"):
        nw.http_fetch(nw.OSV_BATCH_URL, max_bytes=50)


def test_http_fetch_overall_time_limit(monkeypatch):
    _patch_opener(monkeypatch, response=_FakeResponse(b"x" * 100))
    clock = iter([0, 0, 10**6, 10**6, 10**6])
    monkeypatch.setattr(nw.time, "monotonic", lambda: next(clock))
    with pytest.raises(FetchError, match="too long"):
        nw.http_fetch(nw.OSV_BATCH_URL)


def test_http_fetch_refuses_other_ports():
    with pytest.raises(FetchError, match="allowed list"):
        nw.http_fetch("https://api.osv.dev:444/v1/querybatch")
    with pytest.raises(FetchError, match="allowed list"):
        nw.http_fetch("https://api.osv.dev:notaport/v1/querybatch")


@pytest.mark.parametrize("name", ["CON", "NUL", "AUX", "com1"])
def test_windows_device_names_never_become_file_names(tmp_path, name):
    path = nw._vuln_cache_path(tmp_path, name)
    assert path.name.startswith("osv-")


def test_oversized_cache_file_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(nw, "MAX_CACHE_FILE_BYTES", 10)
    path = tmp_path / "big.json"
    path.write_text('{"a": "' + "x" * 100 + '"}', encoding="utf-8")
    assert nw._read_json(path) is None


def test_osv_page_two_failing_leaves_that_purl_unanswered_but_keeps_the_others(tmp_path):
    net = FakeNet()
    pages = {LOG4J_2141: iter([
        {"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q", "modified": "2025-10-22T19:37:02.616807Z"}], "next_page_token": "T"},
    ])}

    def paged(url, body=None, max_bytes=0):
        if url == nw.OSV_BATCH_URL:
            queries = json.loads(body)["queries"]
            if any(q.get("page_token") for q in queries):
                raise FetchError("HTTP 500", 500)
            results = []
            for q in queries:
                purl = q["package"]["purl"]
                results.append(next(pages[purl]) if purl in pages else REAL_BATCH.get(purl, {}))
            return json.dumps({"results": results}).encode()
        return net(url, body, max_bytes)

    purl_vulns, _, status = nw.fetch_osv([LOG4J_2141, PACKAGING], tmp_path, paged, no_sleep, now)
    assert purl_vulns[PACKAGING] == []
    assert purl_vulns[LOG4J_2141] is None
    assert status["status"] == "failed"


def test_osv_many_purls_are_sent_in_chunks(tmp_path, monkeypatch):
    monkeypatch.setattr(nw, "BATCH_SIZE", 2)
    net = FakeNet()
    purls = [f"pkg:pypi/pkg{i}@1.0" for i in range(5)]
    purl_vulns, _, status = nw.fetch_osv(purls, tmp_path, net, no_sleep, now)
    assert net.calls.count(nw.OSV_BATCH_URL) == 3
    assert all(v == [] for v in purl_vulns.values()) and status["status"] == "ok"


def test_osv_with_no_components_says_so(tmp_path):
    _, _, status = nw.fetch_osv([], tmp_path, FakeNet(), no_sleep, now)
    assert status["detail"] == "there was no component to ask about"
    assert status["purls_asked"] == 0


def test_runs_are_ordered_by_their_time_not_by_file_name(tmp_path):
    for i in range(12):  # 12 runs in the same second: -0002 ... -0012
        nw.save_run(tmp_path, {**_run(NOW, {"kev": "ok", "osv": "ok"}), "marker": i}, now)
    assert nw.load_runs(tmp_path)[-1]["marker"] == 11


def test_a_run_with_a_naive_time_does_not_crash_status(tmp_path):
    run = _run(NOW, {"kev": "ok", "osv": "ok"})
    run["finished_at"] = "2026-10-21T12:00:00"  # no time zone
    nw.save_run(tmp_path, run, now)
    text = "\n".join(nw.status_report(tmp_path, now))
    assert "never been a fully successful run" in text
    assert "RESULT INCOMPLETE" in text


def test_a_run_with_garbage_time_does_not_crash_status(tmp_path):
    run = _run(NOW, {"kev": "ok"})
    run["finished_at"] = "not a time"
    nw.save_run(tmp_path, run, now)
    assert "never been a fully successful run" in "\n".join(nw.status_report(tmp_path, now))


def test_a_run_dated_in_the_future_gets_a_clock_warning(tmp_path):
    nw.save_run(tmp_path, _run(NOW + timedelta(hours=5), {"kev": "ok", "osv": "ok"}), now)
    text = "\n".join(nw.status_report(tmp_path, now))
    assert "future" in text and "-" not in text.split("hours ago")[0][-4:]


def test_status_warns_about_components_that_could_not_be_checked(tmp_path):
    run = _run(NOW - timedelta(hours=1), {"kev": "ok", "osv": "ok"})
    run["components"] = {"checked": 4, "unchecked": 1}
    nw.save_run(tmp_path, run, now)
    assert any("1 component(s) could NOT be checked" in line for line in nw.status_report(tmp_path, now))


def test_vulnerability_ids_with_two_dots_are_rejected_not_a_crash(tmp_path):
    net = FakeNet()
    net.batch[LOG4J_2141] = {"vulns": [{"id": "a..b", "modified": "m"}]}
    purl_vulns, _, status = nw.fetch_osv([LOG4J_2141], tmp_path, net, no_sleep, now)
    assert purl_vulns[LOG4J_2141] is None and status["status"] == "failed"


# ---- vuln-0007 (Strix): a KEV list that silently drops known ids must not count as complete ----


def _kev_without(*cve_ids):
    smaller = copy.deepcopy(REAL_KEV)
    smaller["vulnerabilities"] = [e for e in smaller["vulnerabilities"] if e["cveID"] not in cve_ids]
    smaller["count"] = len(smaller["vulnerabilities"])
    return smaller


def test_kev_list_that_drops_known_ids_is_stale_and_names_them(tmp_path):
    nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
    tampered = _kev_without("CVE-2021-44228", "CVE-2021-45046")  # only 2 of ~1750: far below 5%
    data, status = nw.fetch_kev(tmp_path, FakeNet(kev=json.dumps(tampered).encode()), no_sleep, now)
    assert status["status"] == "stale"
    assert status["disappeared_ids"] == ["CVE-2021-44228", "CVE-2021-45046"]
    assert "CVE-2021-44228" in status["detail"] and "human" in status["detail"]
    assert "CVE-2021-44228" in nw.kev_cve_ids(data)  # saved copy still used


def test_the_saved_copy_is_not_overwritten_by_a_list_with_missing_ids(tmp_path):
    nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
    path = tmp_path / "kev" / "kev-saved.json"
    before = path.read_bytes()
    nw.fetch_kev(tmp_path, FakeNet(kev=json.dumps(_kev_without("CVE-2021-44228")).encode()), no_sleep, now)
    assert path.read_bytes() == before


def test_padding_a_list_with_invented_ids_does_not_hide_the_missing_ones(tmp_path):
    nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
    padded = _kev_without("CVE-2021-44228")
    for number in (1, 2):
        padded["vulnerabilities"].append({"cveID": f"CVE-2099-000{number}0", "dateAdded": "2024-01-01"})
    padded["count"] = len(padded["vulnerabilities"])
    _, status = nw.fetch_kev(tmp_path, FakeNet(kev=json.dumps(padded).encode()), no_sleep, now)
    assert status["status"] == "stale"
    assert status["disappeared_ids"] == ["CVE-2021-44228"]


def test_a_list_that_only_adds_ids_is_still_accepted(tmp_path):
    nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
    bigger = copy.deepcopy(REAL_KEV)
    bigger["vulnerabilities"].append({"cveID": "CVE-2099-00010", "dateAdded": "2024-01-01"})
    bigger["count"] = len(bigger["vulnerabilities"])
    _, status = nw.fetch_kev(tmp_path, FakeNet(kev=json.dumps(bigger).encode()), no_sleep, now)
    assert status["status"] == "ok"


def test_a_run_with_dropped_kev_ids_is_incomplete(tmp_path):
    nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
    net = FakeNet(kev=json.dumps(_kev_without("CVE-2021-44228")).encode())
    feeds = nw.collect([component(LOG4J_2141)], tmp_path, net, no_sleep, now)
    assert feeds.kev_status["status"] == "stale"
    assert not feeds.complete
    assert "CVE-2021-44228" in feeds.kev_ids  # the saved copy still protects us


# ---- vuln-0013 (Strix): a run file that is too big to read must never be skipped silently ----


def test_an_oversized_latest_run_file_is_never_skipped(tmp_path, monkeypatch):
    import os
    nw.save_run(tmp_path, _run(NOW - timedelta(hours=5), {"kev": "ok", "osv": "ok"}), lambda: NOW - timedelta(hours=5))
    big = tmp_path / "2026-01-01T00-00-00Z-big.json"
    big.write_text('{"finished_at": "x", "pad": "' + "x" * 5000 + '"}', encoding="utf-8")
    newer = (NOW - timedelta(hours=1)).timestamp()
    os.utime(big, (newer, newer))
    monkeypatch.setattr(nw, "MAX_CACHE_FILE_BYTES", 2000)
    lines, ok = nw.status_summary(tmp_path, now)
    text = "\n".join(lines)
    assert ok is False
    assert "RESULT INCOMPLETE" in text
    assert "too large" in text
    assert "Latest run: all sources ok." not in text


@pytest.mark.parametrize("content", ["{ nope", "[1, 2]", '{"finished_at": "2026-01-01T00:00:00"}', '{"finished_at": 5}'])
def test_an_unreadable_newer_run_file_hides_no_older_clean_run(tmp_path, content):
    import os
    nw.save_run(tmp_path, _run(NOW - timedelta(hours=5), {"kev": "ok", "osv": "ok"}), lambda: NOW - timedelta(hours=5))
    bad = tmp_path / "zz-bad.json"
    bad.write_text(content, encoding="utf-8")
    newer = (NOW - timedelta(hours=1)).timestamp()
    os.utime(bad, (newer, newer))
    lines, ok = nw.status_summary(tmp_path, now)
    assert ok is False
    assert "Latest run: all sources ok." not in "\n".join(lines)


# ---- vuln-0001 (Strix), the simple safe part: a run record that cannot be verified is never "all sources ok" ----


def _healthy_planted_run(finished):
    return {"finished_at": finished.isoformat(), "complete": True, "report_cases": 0, "needs_human": False,
            "sources": {"kev": {"status": "ok"}, "osv": {"status": "ok"}}, "components": {"checked": 1, "unchecked": 0}}


def test_a_planted_unsealed_healthy_run_does_not_hide_the_real_report_case(tmp_path):
    real = _run(NOW - timedelta(hours=3), {"kev": "ok", "osv": "ok"})
    real.update({"report_cases": 2, "needs_human": True, "components": {"checked": 1, "unchecked": 0}})
    nw.save_run(tmp_path, real, lambda: NOW - timedelta(hours=3))
    planted = tmp_path / "2026-10-25T00-00-00Z-planted.json"
    planted.write_text(json.dumps(_healthy_planted_run(NOW - timedelta(hours=1))), encoding="utf-8")
    lines, ok = nw.status_summary(tmp_path, now)
    text = "\n".join(lines)
    assert ok is False
    assert "Latest run: all sources ok." not in text
    assert "RESULT INCOMPLETE" in text and "seal" in text


def test_a_run_record_edited_after_saving_is_not_trusted(tmp_path):
    real = _run(NOW - timedelta(hours=1), {"kev": "ok", "osv": "ok"})
    real.update({"report_cases": 2, "needs_human": True, "components": {"checked": 1, "unchecked": 0}})
    path = nw.save_run(tmp_path, real, lambda: NOW - timedelta(hours=1))
    edited = json.loads(path.read_text(encoding="utf-8"))
    edited["report_cases"] = 0
    edited["needs_human"] = False
    path.write_text(json.dumps(edited), encoding="utf-8")
    lines, ok = nw.status_summary(tmp_path, now)
    assert ok is False
    assert "REPORT CASE" not in "\n".join(lines) or "RESULT INCOMPLETE" in "\n".join(lines)
    assert "Latest run: all sources ok." not in "\n".join(lines)


def test_a_normally_saved_run_is_sealed_and_verifies(tmp_path):
    nw.save_run(tmp_path, _run(NOW - timedelta(hours=1), {"kev": "ok", "osv": "ok"}), lambda: NOW - timedelta(hours=1))
    lines, ok = nw.status_summary(tmp_path, now)
    assert "Latest run: all sources ok." in lines and ok is True


# ---- vuln-0002 (Strix): status must not load every run file, and a dropped file must never look clean ----


def test_load_runs_keeps_only_the_newest_and_the_newest_complete_run(tmp_path):
    for hours in (9, 8, 7):
        nw.save_run(tmp_path, _run(NOW - timedelta(hours=hours), {"kev": "ok", "osv": "ok"}), lambda h=hours: NOW - timedelta(hours=h))
    nw.save_run(tmp_path, _run(NOW - timedelta(hours=1), {"kev": "failed", "osv": "ok"}), lambda: NOW - timedelta(hours=1))
    kept = nw.load_runs(tmp_path)
    assert len(kept) == 2  # the newest (failed) run and the newest complete run, nothing else


def test_a_folder_over_the_total_byte_budget_is_incomplete_never_clean(tmp_path, monkeypatch):
    for hours in (5, 4, 3, 2):
        nw.save_run(tmp_path, _run(NOW - timedelta(hours=hours), {"kev": "ok", "osv": "ok"}), lambda h=hours: NOW - timedelta(hours=h))
    one_file = max(p.stat().st_size for p in tmp_path.glob("*.json"))
    monkeypatch.setattr(nw, "MAX_RUN_TOTAL_BYTES", one_file * 2)
    lines, ok = nw.status_summary(tmp_path, now)
    text = "\n".join(lines)
    assert ok is False
    assert "RESULT INCOMPLETE" in text and "budget" in text
    assert "Latest run: all sources ok." not in text


# ---- vuln-0008 (Strix): a KEV list dated in the future must not freeze the saved copy ----


def _kev_released(when):
    changed = copy.deepcopy(REAL_KEV)
    changed["dateReleased"] = when.isoformat()
    return json.dumps(changed).encode()


def test_a_future_dated_kev_list_is_rejected_and_does_not_freeze_updates(tmp_path):
    nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
    _, status = nw.fetch_kev(tmp_path, FakeNet(kev=_kev_released(NOW + timedelta(days=400))), no_sleep, now)
    assert status["status"] == "stale" and "future" in status["detail"]
    # a later genuine download (dated before now, after the saved copy) is still accepted
    genuine = _kev_released(NOW - timedelta(hours=1))
    _, status = nw.fetch_kev(tmp_path, FakeNet(kev=genuine), no_sleep, now)
    assert status["status"] == "ok"


def test_a_saved_kev_copy_dated_in_the_future_is_discarded(tmp_path):
    nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
    path = tmp_path / "kev" / "kev-saved.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    saved["data"]["dateReleased"] = (NOW + timedelta(days=400)).isoformat()
    path.write_text(json.dumps(saved), encoding="utf-8")
    assert nw.load_kev_cache(tmp_path, now) == (None, None)


def test_a_kev_list_released_a_few_hours_ahead_is_still_accepted():
    ahead = json.loads(_kev_released(NOW + timedelta(hours=3)))
    assert nw.validate_kev(ahead, now=NOW) is None


# ---- vuln-0009 (Strix): the total time limit must hold while a server drips bytes ----


def test_http_fetch_total_time_limit_holds_against_a_dripping_server(monkeypatch):
    import http.client
    import socket
    import threading
    import time

    server, client = socket.socketpair()
    stop = threading.Event()

    def drip():
        try:
            server.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            for _ in range(200):  # one byte every 0.05 s: about 10 s in total
                if stop.is_set():
                    break
                server.sendall(b"x")
                time.sleep(0.05)
        except OSError:
            pass
        finally:
            server.close()

    thread = threading.Thread(target=drip, daemon=True)
    thread.start()
    response = http.client.HTTPResponse(client)
    response.begin()
    _patch_opener(monkeypatch, response=response)
    monkeypatch.setattr(nw, "TOTAL_SECONDS", 0.3)
    started = time.monotonic()
    try:
        with pytest.raises(FetchError, match="too long"):
            nw.http_fetch(nw.OSV_BATCH_URL)
        elapsed = time.monotonic() - started
    finally:
        stop.set()
        client.close()
        thread.join(timeout=2)
    assert elapsed < 2.0  # the old code waited for the whole 64 KB read (about 10 s)
