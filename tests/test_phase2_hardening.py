"""Tests for the Phase 2 end-of-phase review findings (architect, code reviewer, and the pen-tester's hypotheses)."""

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src import matcher, news_watcher as nw
from src.cli import PROJECT_ROOT, build_parser, main
from src.matcher import AFFECTED, UNKNOWN
from src.sbom_reader import Component
from tests.test_cli_run import SBOM, clock, run_cli, saved_run, write_sbom
from tests.test_matcher import LOG4SHELL, REQUESTS_CVE, osv
from tests.test_news_watcher import (
    LOG4J_2141, PACKAGING, REAL_KEV, REAL_KEV_BYTES, FakeNet, no_sleep, now,
)

NOW = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------------ failed runs leave a record


def test_a_crashed_run_leaves_a_failed_record_that_status_shows(tmp_path, capsys, monkeypatch):
    clean = write_sbom(tmp_path, ["pkg:pypi/packaging@24.1"])
    run_cli(tmp_path, sbom=clean)  # a good run at 12:00
    capsys.readouterr()

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("src.matcher.evaluate", boom)
    later = lambda: NOW + timedelta(hours=2)
    code = run_cli(tmp_path, sbom=clean, now=later)
    assert code == 1
    assert "failed run was saved" in capsys.readouterr().out

    code = main(["status", "--runs", str(tmp_path / "runs")], now=later)
    out = capsys.readouterr().out
    assert code == 1
    assert "RESULT INCOMPLETE" in out  # the older good run no longer hides the crash
    assert "Last successful run" in out


def test_an_unusable_cache_folder_also_leaves_a_failed_record(tmp_path, capsys):
    (tmp_path / "cache").write_text("a file, not a folder", encoding="utf-8")
    run_cli(tmp_path)
    capsys.readouterr()
    records = [json.loads(p.read_text(encoding="utf-8")) for p in (tmp_path / "runs").glob("*.json")]
    assert len(records) == 1 and records[0]["complete"] is False and records[0]["error"]


def test_if_even_the_failed_record_cannot_be_saved_it_says_so(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("src.matcher.evaluate", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    (tmp_path / "runs").write_text("a file", encoding="utf-8")
    assert run_cli(tmp_path) == 1
    assert "could NOT be saved either" in capsys.readouterr().out


# ------------------------------------------------------------------ no free text is saved


def test_the_real_osv_record_does_have_free_text_but_the_saved_copy_does_not(tmp_path):
    raw = json.loads((Path(__file__).parent / "fixtures" / "osv" / "GHSA-jfh8-c2jp-5v3q.json").read_text(encoding="utf-8"))
    assert "summary" in raw and "details" in raw and "references" in raw  # so the test below is meaningful
    purl_vulns, vulns, _ = nw.fetch_osv([LOG4J_2141], tmp_path, FakeNet(), no_sleep, now)
    saved_text = (tmp_path / "osv" / "osv-GHSA-jfh8-c2jp-5v3q.json").read_text(encoding="utf-8")
    for key in ("summary", "details", "references", "severity", "database_specific", "schema_version"):
        assert f'"{key}"' not in saved_text
        assert key not in vulns["GHSA-jfh8-c2jp-5v3q"]
    assert raw["summary"] not in saved_text


def test_the_slim_record_keeps_what_the_matcher_needs():
    raw = osv("GHSA-jfh8-c2jp-5v3q")
    slim = nw.slim_osv_record(raw)
    assert slim["id"] == raw["id"] and slim["aliases"] == ["CVE-2021-44228"]
    purl = "pkg:maven/org.apache.logging.log4j/log4j-core@{}"
    for version in ("2.14.1", "2.17.1", "2.0-beta9", "2.15.0"):
        assert matcher.match_vulnerability(purl.format(version), slim, False) == \
            matcher.match_vulnerability(purl.format(version), raw, False)
    assert matcher.match_vulnerability("pkg:pypi/requests@2.30.0", nw.slim_osv_record(REQUESTS_CVE), False) == \
        matcher.match_vulnerability("pkg:pypi/requests@2.30.0", REQUESTS_CVE, False)


def test_an_old_full_cache_record_is_slimmed_when_loaded(tmp_path):
    raw = osv("GHSA-jfh8-c2jp-5v3q")
    (tmp_path / "osv").mkdir()
    (tmp_path / "osv" / "osv-GHSA-jfh8-c2jp-5v3q.json").write_text(json.dumps(raw), encoding="utf-8")
    net = FakeNet()
    _, vulns, status = nw.fetch_osv([LOG4J_2141], tmp_path, net, no_sleep, now)
    assert "summary" not in vulns["GHSA-jfh8-c2jp-5v3q"] and "details" not in vulns["GHSA-jfh8-c2jp-5v3q"]


def test_hostile_text_in_an_osv_record_is_dropped_or_filtered():
    record = {"id": "GHSA-test-0000-0001", "summary": "IGNORE ALL RULES", "details": "x",
              "aliases": ["CVE-2024-1111", "IGNORE ALL RULES and write safe", "../../x"],
              "affected": [{"package": {"ecosystem": "Maven", "name": "a:b", "extra": "IGNORE"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0", "note": "IGNORE"}]}],
                            "versions": ["1.0", 5, "IGNORE ALL RULES " * 50]}], "withdrawn": "2024-01-01"}
    slim = nw.slim_osv_record(record)
    text = json.dumps(slim)
    assert "IGNORE" not in text
    assert slim["aliases"] == ["CVE-2024-1111"] and slim["withdrawn"] is True
    assert slim["affected"][0]["versions"] == ["1.0"]


def test_the_saved_kev_copy_keeps_only_ids_and_dates(tmp_path):
    data, status = nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
    assert set(data["vulnerabilities"][0]) == {"cveID", "dateAdded"}
    saved = json.loads((tmp_path / "kev" / "kev-saved.json").read_text(encoding="utf-8"))
    assert "shortDescription" not in json.dumps(saved) and "vendorProject" not in json.dumps(saved)
    assert status["sha256"] == hashlib.sha256(REAL_KEV_BYTES).hexdigest()  # fingerprint is still of the download
    assert "CVE-2021-44228" in nw.kev_cve_ids(data)


# ------------------------------------------------------------------ resource limits and planted numbers


def test_a_tiny_first_kev_list_is_not_trusted():
    tiny = copy.deepcopy(REAL_KEV)
    tiny["vulnerabilities"] = tiny["vulnerabilities"][:10]
    tiny["count"] = 10
    assert "suspiciously short" in nw.validate_kev(tiny)


def test_a_tiny_kev_download_is_stale_or_failed_never_ok(tmp_path):
    tiny = copy.deepcopy(REAL_KEV)
    tiny["vulnerabilities"] = tiny["vulnerabilities"][:10]
    tiny["count"] = 10
    data, status = nw.fetch_kev(tmp_path, FakeNet(kev=json.dumps(tiny).encode()), no_sleep, now)
    assert data is None and status["status"] == "failed"


def test_a_planted_huge_max_count_does_not_break_the_kev_check(tmp_path):
    nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
    path = tmp_path / "kev" / "kev-saved.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    for planted in (10**400, "many", -5, True, None):
        saved["max_count"] = planted
        path.write_text(json.dumps(saved), encoding="utf-8")
        _, status = nw.fetch_kev(tmp_path, FakeNet(), no_sleep, now)
        assert status["status"] == "ok"


def test_too_many_vulnerabilities_for_one_component_is_not_trusted(tmp_path, monkeypatch):
    monkeypatch.setattr(nw, "MAX_IDS_PER_PURL", 2)
    purl_vulns, _, status = nw.fetch_osv([LOG4J_2141], tmp_path, FakeNet(), no_sleep, now)
    assert purl_vulns[LOG4J_2141] is None and status["status"] == "failed"


def test_a_limit_on_detail_downloads_leaves_the_rest_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr(nw, "MAX_DETAIL_REQUESTS", 2)
    net = FakeNet()
    _, vulns, status = nw.fetch_osv([LOG4J_2141], tmp_path, net, no_sleep, now)
    assert net.vuln_calls == 2
    assert sum(v is None for v in vulns.values()) == len(vulns) - 2
    assert status["status"] == "failed"


def test_a_huge_version_list_is_unknown_not_slow(monkeypatch):
    monkeypatch.setattr(matcher, "MAX_VERSIONS", 2)
    record = {"id": "GHSA-test-0000-0002", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "lib"}, "versions": ["1", "2", "3"]}]}
    assert matcher.match_vulnerability("pkg:pypi/lib@9", record, False) == (UNKNOWN, "version_list_too_long")
    record["affected"][0]["package"] = {"ecosystem": "Maven", "name": "o:lib"}
    assert matcher.match_vulnerability("pkg:maven/o/lib@9", record, False) == (UNKNOWN, "version_list_too_long")


# ------------------------------------------------------------------ evidence files


def feeds_with(purl, vuln_id, record, kev_ids=frozenset()):
    return nw.Feeds(kev_ids=set(kev_ids), kev_status={"status": "ok"}, purl_vulns={purl: [vuln_id]}, vulns={vuln_id: record})


def requests_component():
    return Component("requests", "2.30.0", "pkg:pypi/requests@2.30.0", "pypi", "OK")


def test_a_broken_evidence_file_means_urgent_review_not_quietly_not_exploited(tmp_path):
    (tmp_path / "CVE-2023-32681.json").write_text("{ broken", encoding="utf-8")
    feeds = feeds_with("pkg:pypi/requests@2.30.0", "GHSA-j8r2-6x86-q33q", REQUESTS_CVE)
    (finding,) = matcher.evaluate([requests_component()], feeds, tmp_path)["findings"]
    assert finding["status"] == AFFECTED and finding["exploited"] is False
    assert finding["exploited_known"] is False and finding["action"] == "URGENT_HUMAN_REVIEW"
    assert finding["evidence_problem"] == ["CVE-2023-32681"]


def test_a_valid_evidence_file_leaves_a_trail_in_the_finding(tmp_path):
    (tmp_path / "CVE-2023-32681.json").write_text(
        json.dumps({"source_url": "https://example.org/report", "date": "2026-10-01"}), encoding="utf-8")
    feeds = feeds_with("pkg:pypi/requests@2.30.0", "GHSA-j8r2-6x86-q33q", REQUESTS_CVE)
    (finding,) = matcher.evaluate([requests_component()], feeds, tmp_path)["findings"]
    assert finding["evidence"] == {"source_url": "https://example.org/report", "date": "2026-10-01"}
    assert finding["action"] == "REPORT_CASE" and finding["evidence_problem"] == []


def test_no_evidence_file_at_all_is_normal(tmp_path):
    feeds = feeds_with("pkg:pypi/requests@2.30.0", "GHSA-j8r2-6x86-q33q", REQUESTS_CVE)
    (finding,) = matcher.evaluate([requests_component()], feeds, tmp_path)["findings"]
    assert finding["exploited_known"] is True and finding["evidence"] is None and finding["action"] == "RECORD"


def test_run_output_shows_the_evidence_link_and_an_unusable_file_warning(tmp_path, capsys):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "CVE-2023-32681.json").write_text(
        json.dumps({"source_url": "https://example.org/report", "date": "2026-10-01"}), encoding="utf-8")
    run_cli(tmp_path)
    assert "[evidence: https://example.org/report, dated 2026-10-01]" in capsys.readouterr().out
    (tmp_path / "evidence" / "CVE-2023-32681.json").write_text("{ broken", encoding="utf-8")
    run_cli(tmp_path)
    assert "exists but is UNUSABLE: fix it" in capsys.readouterr().out


# ------------------------------------------------------------------ folders, product, package summary


def test_default_folders_are_absolute_and_next_to_the_program():
    parser = build_parser()
    run_args = parser.parse_args(["run", "--sbom", "a", "--config", "b"])
    status_args = parser.parse_args(["status"])
    for value in (run_args.cache, run_args.runs, run_args.evidence, status_args.runs):
        assert Path(value).is_absolute()
    assert Path(run_args.runs) == PROJECT_ROOT / "runs" == Path(status_args.runs)


def test_run_prints_folders_and_notes_a_missing_evidence_folder(tmp_path, capsys):
    run_cli(tmp_path)
    out = capsys.readouterr().out
    assert "Folders: cache=" in out and "evidence=" in out
    assert "the evidence folder does not exist" in out
    assert saved_run(tmp_path)["folders"]["evidence_folder_exists"] is False


def test_run_record_contains_the_sbom_fingerprint_and_product(tmp_path):
    run_cli(tmp_path)
    run = saved_run(tmp_path)
    assert run["sbom_sha256"] == hashlib.sha256(Path(SBOM).read_bytes()).hexdigest()
    assert run["product"]["product_name"] == "SmartHeat X1 Thermostat"


def test_run_prints_one_answer_per_package(tmp_path, capsys):
    run_cli(tmp_path)
    out = capsys.readouterr().out
    assert "maven:org.apache.logging.log4j:log4j-core: AFFECTED" in out  # 2.14.1 AFFECTED wins over 2.17.1
    assert "pypi:requests: AFFECTED" in out


# ------------------------------------------------------------------ cut-off lists must be marked


def _big_record(count):
    return {"id": "GHSA-test-0000-0009", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "lib"}, "versions": [f"1.{i}" for i in range(count)]}]}


def test_a_long_list_is_marked_as_truncated(monkeypatch):
    monkeypatch.setattr(nw, "MAX_VERSIONS_PER_ENTRY", 3)
    assert nw.slim_osv_record(_big_record(5))["truncated"] is True
    assert "truncated" not in nw.slim_osv_record(_big_record(3))


def test_a_truncated_record_can_never_say_not_affected(monkeypatch):
    monkeypatch.setattr(nw, "MAX_VERSIONS_PER_ENTRY", 3)
    slim = nw.slim_osv_record(_big_record(5))  # versions 1.0 .. 1.4 cut to 1.0 .. 1.2
    assert matcher.match_vulnerability("pkg:pypi/lib@1.4", slim, False) == (UNKNOWN, "record_truncated")
    assert matcher.match_vulnerability("pkg:pypi/lib@1.1", slim, False)[0] == AFFECTED  # a clear hit still counts


def test_truncation_of_events_ranges_and_entries_is_marked(monkeypatch):
    many_events = {"id": "GHSA-test-0000-0010", "affected": [{"package": {"ecosystem": "Maven", "name": "a:b"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}] * 2001}]}]}
    assert nw.slim_osv_record(many_events)["truncated"] is True
    many_ranges = {"id": "GHSA-test-0000-0011", "affected": [{"package": {"ecosystem": "Maven", "name": "a:b"},
                   "ranges": [{"type": "ECOSYSTEM", "events": []}] * 101}]}
    assert nw.slim_osv_record(many_ranges)["truncated"] is True
    many_entries = {"id": "GHSA-test-0000-0012", "affected": [{"package": {"ecosystem": "Maven", "name": "a:b"}}] * 2001}
    assert nw.slim_osv_record(many_entries)["truncated"] is True


def test_the_real_records_are_not_marked_truncated():
    for name in ("GHSA-jfh8-c2jp-5v3q", "GHSA-j8r2-6x86-q33q", "PYSEC-2023-74"):
        assert "truncated" not in nw.slim_osv_record(osv(name))


# ------------------------------------------------------------------ conditions from the meeting


def test_a_withdrawn_advisory_is_still_ignored_after_the_cache_round_trip(tmp_path):
    withdrawn = dict(osv("GHSA-jfh8-c2jp-5v3q"), withdrawn="2024-01-01T00:00:00Z")
    net = FakeNet()
    net.vuln_overrides["GHSA-jfh8-c2jp-5v3q"] = json.dumps(withdrawn).encode()
    comp = Component("log4j-core", "2.14.1", LOG4J_2141, "maven", "OK")
    for _ in range(2):  # first run downloads and saves, second run loads from the saved copy
        feeds = nw.collect([comp], tmp_path, net, no_sleep, now)
        result = matcher.evaluate([comp], feeds)
        assert "GHSA-jfh8-c2jp-5v3q" in result["ignored_withdrawn_ids"]
        assert all(f["vulnerability_id"] != "GHSA-jfh8-c2jp-5v3q" for f in result["findings"])


def test_the_slim_copy_keeps_every_field_the_matcher_reads():
    slim = nw.slim_osv_record(dict(osv("GHSA-jfh8-c2jp-5v3q"), upstream=["CVE-2021-44228"], withdrawn="x"))
    assert {"id", "modified", "aliases", "upstream", "withdrawn", "affected"} <= set(slim)
    package = slim["affected"][0]["package"]
    assert package["ecosystem"] == "Maven" and package["name"].startswith("org.apache.logging.log4j")


def _incomplete(tmp_path, capsys, code_expected=None):
    out = capsys.readouterr().out
    run = saved_run(tmp_path)
    assert run["complete"] is False
    assert "RESULT INCOMPLETE" in out and "No exploited vulnerabilities found" not in out
    return out


def test_cap_on_ids_per_component_makes_the_run_incomplete(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(nw, "MAX_IDS_PER_PURL", 2)
    run_cli(tmp_path, sbom=write_sbom(tmp_path, ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"]))
    out = _incomplete(tmp_path, capsys)
    assert "osv_gave_no_answer" in out and "Source OSV: failed" in out


def test_cap_on_detail_downloads_makes_the_run_incomplete(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(nw, "MAX_DETAIL_REQUESTS", 1)
    run_cli(tmp_path, sbom=write_sbom(tmp_path, ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"]))
    out = _incomplete(tmp_path, capsys)
    assert "osv_details_missing" in out and "Source OSV: failed" in out


def test_cap_on_version_list_length_makes_the_run_incomplete(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(matcher, "MAX_VERSIONS", 2)
    run_cli(tmp_path, sbom=write_sbom(tmp_path, ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"]))
    out = _incomplete(tmp_path, capsys)
    assert "version_list_too_long" in out and "could not be judged" in out
    assert saved_run(tmp_path)["result"]["data_gaps"] > 0


def test_a_truncated_record_makes_the_run_incomplete(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(nw, "MAX_VERSIONS_PER_ENTRY", 1)
    net = FakeNet()
    # pretend OSV lists the advisory for 2.31.0 (the fixed version): only the cut-off list could decide this
    net.batch["pkg:pypi/requests@2.31.0"] = {"vulns": [{"id": "GHSA-j8r2-6x86-q33q", "modified": "2026-09-10T03:50:01.756149Z"}]}
    run_cli(tmp_path, net, sbom=write_sbom(tmp_path, ["pkg:pypi/requests@2.31.0"]))
    out = _incomplete(tmp_path, capsys)
    assert "record_truncated" in out and "could not be judged" in out


def test_status_says_the_26_hour_warning_is_not_a_deadline_guarantee(tmp_path):
    put_run_ok = {"finished_at": NOW.isoformat(), "complete": True,
                  "sources": {"kev": {"status": "ok"}, "osv": {"status": "ok"}}, "components": {"unchecked": 0}}
    nw.save_run(tmp_path, put_run_ok, lambda: NOW)
    lines, ok = nw.status_summary(tmp_path, lambda: NOW + timedelta(hours=1))
    assert ok
    assert any("can fire after the deadline has already passed" in line for line in lines)
    assert not any("WARNING" in line for line in lines)


def test_status_warns_about_data_gaps_in_the_latest_run(tmp_path):
    run = {"finished_at": NOW.isoformat(), "complete": True, "result": {"data_gaps": 3},
           "sources": {"kev": {"status": "ok"}, "osv": {"status": "ok"}}, "components": {"unchecked": 0}}
    nw.save_run(tmp_path, run, lambda: NOW)
    lines, ok = nw.status_summary(tmp_path, lambda: NOW)
    assert not ok and any("3 finding(s)" in line for line in lines)
