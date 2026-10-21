"""End-to-end tests for `cra run` and `cra status` on the fake demo product (offline, real saved data)."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src import news_watcher as nw
from src.cli import main
from tests.test_news_watcher import FakeNet, no_sleep

DEMO = Path(__file__).parent.parent / "demo-data"
SBOM = str(DEMO / "demo-thermostat-sbom.json")
CONFIG = str(DEMO / "demo-product-config.json")
NOW = datetime(2026, 10, 21, 12, 0, 0, tzinfo=timezone.utc)


def clock():
    return NOW


def run_cli(tmp_path, net=None, extra=(), sbom=SBOM, now=clock):
    args = ["run", "--sbom", sbom, "--config", CONFIG, "--cache", str(tmp_path / "cache"),
            "--runs", str(tmp_path / "runs"), "--evidence", str(tmp_path / "evidence"), *extra]
    return main(args, fetch=net or FakeNet(), sleep=no_sleep, now=now)


def saved_run(tmp_path):
    (path,) = (tmp_path / "runs").glob("*.json")
    return json.loads(path.read_text(encoding="utf-8"))


def write_sbom(tmp_path, purls):
    comps = []
    for i, purl in enumerate(purls):
        name = purl.split("/")[-1].split("@")[0]
        comps.append({"name": name, "version": purl.split("@")[1], "purl": purl})
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "components": comps, "dependencies": [{"ref": "a"}]}),
                    encoding="utf-8")
    return str(path)


def test_demo_run_finds_the_log4shell_report_case(tmp_path, capsys):
    code = run_cli(tmp_path)
    out = capsys.readouterr().out
    assert code == 3
    assert "REPORT CASE" in out
    assert "log4j-core 2.14.1: GHSA-jfh8-c2jp-5v3q (CVE-2021-44228) -> AFFECTED" in out
    assert "ACTIVELY EXPLOITED per kev (CVE-2021-44228)" in out
    assert "CVE-2021-45046" in out  # also in KEV
    assert "Source KEV: ok" in out and "Source OSV: ok" in out


def test_demo_run_says_so_when_a_component_could_not_be_checked(tmp_path, capsys):
    run_cli(tmp_path)
    out = capsys.readouterr().out
    assert "not checkable (UNKNOWN): 1" in out
    assert "RESULT INCOMPLETE" in out
    assert "No exploited vulnerabilities found" not in out


def test_demo_run_never_claims_to_send_and_always_prints_the_kev_note(tmp_path, capsys):
    run_cli(tmp_path)
    out = capsys.readouterr().out
    assert "Nothing was sent. A human decides" in out
    assert "KEV is a floor, not a ceiling" in out


def test_demo_run_is_saved_with_sources_and_counts(tmp_path):
    run_cli(tmp_path)
    run = saved_run(tmp_path)
    assert run["sources"]["kev"]["status"] == "ok" and run["sources"]["osv"]["status"] == "ok"
    assert run["components"] == {"checked": 4, "unchecked": 1}
    assert run["product"]["member_states"] == ["DE", "AT", "FR"]
    assert run["finished_at"] == NOW.isoformat()
    unknown = [f for f in run["result"]["findings"] if f["rule"].startswith("component_unknown")]
    assert len(unknown) == 1 and unknown[0]["component"] == "smartheat-firmware-core"


def test_demo_run_log4j_2_17_1_is_not_a_log4shell_case(tmp_path):
    run_cli(tmp_path)
    findings = saved_run(tmp_path)["result"]["findings"]
    for f in findings:
        if f["version"] == "2.17.1":
            assert "CVE-2021-44228" not in f["cve_ids"]


def test_requests_is_recorded_but_not_a_report_case(tmp_path, capsys):
    run_cli(tmp_path)
    out = capsys.readouterr().out
    assert "[Recorded (affected, not known to be exploited)] requests 2.30.0" in out
    assert not [line for line in out.splitlines() if line.startswith("[REPORT CASE") and "requests" in line]


def test_failed_kev_means_incomplete_and_never_a_quiet_recorded(tmp_path, capsys):
    net = FakeNet(kev=nw.FetchError("HTTP 503", 503))
    code = run_cli(tmp_path, net)
    out = capsys.readouterr().out
    assert code == 1
    assert "Source KEV: failed" in out
    assert "RESULT INCOMPLETE" in out
    assert "could NOT check if it is exploited" in out
    assert "REPORT CASE" not in out and "Recorded (affected" not in out
    assert "URGENT HUMAN REVIEW" in out


def test_osv_429_forever_means_unknown_components_and_incomplete(tmp_path, capsys):
    net = FakeNet()
    net.batch_error = nw.FetchError("HTTP 429", 429)
    code = run_cli(tmp_path, net)
    out = capsys.readouterr().out
    assert code == 1
    assert "Source OSV: failed" in out
    assert "osv_gave_no_answer" in out
    assert "RESULT INCOMPLETE" in out and "No exploited vulnerabilities found" not in out


def test_a_fully_checked_clean_product_gets_the_all_clear_message(tmp_path, capsys):
    sbom = write_sbom(tmp_path, ["pkg:pypi/packaging@24.1"])
    code = run_cli(tmp_path, sbom=sbom)
    out = capsys.readouterr().out
    assert code == 0
    assert "No exploited vulnerabilities found in the checked components (all sources ok)." in out
    assert "RESULT INCOMPLETE" not in out


def test_a_human_evidence_file_makes_requests_a_report_case(tmp_path, capsys):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "CVE-2023-32681.json").write_text(
        json.dumps({"source_url": "https://example.org/report", "date": "2026-10-01"}), encoding="utf-8")
    code = run_cli(tmp_path)
    out = capsys.readouterr().out
    assert code == 3
    assert "requests 2.30.0: GHSA-j8r2-6x86-q33q (CVE-2023-32681) -> AFFECTED" in out
    assert "ACTIVELY EXPLOITED per evidence_file" in out
    assert "linked through an alias: a human should confirm" in out


def test_a_bad_sbom_is_rejected_before_any_download(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"bomFormat": "SPDX"}', encoding="utf-8")
    calls = []

    def fetch(*args):
        calls.append(args)
        raise AssertionError("must not download")

    code = main(["run", "--sbom", str(bad), "--config", CONFIG, "--cache", str(tmp_path / "c"),
                 "--runs", str(tmp_path / "r")], fetch=fetch, sleep=no_sleep, now=clock)
    assert code == 2 and not calls
    assert "REJECTED" in capsys.readouterr().err
    assert not (tmp_path / "r").exists()


def test_a_bad_config_is_rejected(tmp_path, capsys):
    bad = tmp_path / "config.json"
    bad.write_text('{"product_name": "P", "manufacturer": "M", "member_states": []}', encoding="utf-8")
    code = main(["run", "--sbom", SBOM, "--config", str(bad)], fetch=FakeNet(), sleep=no_sleep, now=clock)
    assert code == 2
    assert "REJECTED" in capsys.readouterr().err


def test_a_second_run_uses_saved_records_and_downloads_less(tmp_path):
    first = FakeNet()
    run_cli(tmp_path, first)
    second = FakeNet()
    run_cli(tmp_path, second)
    assert first.vuln_calls > 0 and second.vuln_calls == 0


# ------------------------------------------------------------------ cra status


def test_status_without_any_run_warns(tmp_path, capsys):
    code = main(["status", "--runs", str(tmp_path / "runs")], now=clock)
    assert code == 1
    assert "no run found" in capsys.readouterr().out


def test_status_after_a_complete_run_in_the_last_hours(tmp_path, capsys):
    run_cli(tmp_path, sbom=write_sbom(tmp_path, ["pkg:pypi/packaging@24.1"]))
    capsys.readouterr()
    later = lambda: NOW + timedelta(hours=3)
    code = main(["status", "--runs", str(tmp_path / "runs")], now=later)
    out = capsys.readouterr().out
    assert code == 0
    assert "3 hours ago" in out and "all sources ok" in out


def test_status_warns_after_26_hours(tmp_path, capsys):
    run_cli(tmp_path, sbom=write_sbom(tmp_path, ["pkg:pypi/packaging@24.1"]))
    capsys.readouterr()
    code = main(["status", "--runs", str(tmp_path / "runs")], now=lambda: NOW + timedelta(hours=27))
    assert code == 1
    assert "more than 26 hours ago" in capsys.readouterr().out


def test_status_warns_about_components_that_were_not_checked(tmp_path, capsys):
    run_cli(tmp_path)  # the demo has one component without a purl
    capsys.readouterr()
    code = main(["status", "--runs", str(tmp_path / "runs")], now=lambda: NOW + timedelta(hours=1))
    out = capsys.readouterr().out
    assert code == 1
    assert "1 component(s) could NOT be checked" in out


def test_status_after_a_failed_run_says_result_incomplete(tmp_path, capsys):
    run_cli(tmp_path, FakeNet(kev=nw.FetchError("down")))
    capsys.readouterr()
    code = main(["status", "--runs", str(tmp_path / "runs")], now=clock)
    out = capsys.readouterr().out
    assert code == 1
    assert "RESULT INCOMPLETE" in out and "kev: failed" in out
