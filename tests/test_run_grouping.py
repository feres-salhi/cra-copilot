"""Improvement 5: `cra run` shows one vulnerability once, with all its ids (GHSA, PYSEC ...). DISPLAY ONLY:
the matching and the run record are not changed."""
import copy
import json

from src import cli, matcher
from tests.test_cli_run import SBOM, run_cli, saved_run


def finding(vuln_id, cves=("CVE-2024-1",), **extra):
    base = {
        "action": "RECORD", "component": "requests", "cve_ids": list(cves), "ecosystem": "pypi", "evidence": None,
        "evidence_problem": [], "exploited": False, "exploited_cve": None, "exploited_cve_matched_on": None,
        "exploited_known": True, "exploited_via": None, "purl": "pkg:pypi/requests@2.30.0", "rule": "osv_exact_version_list",
        "status": "AFFECTED", "version": "2.30.0", "vulnerability_id": vuln_id,
    }
    return {**base, **extra}


def test_the_same_cve_under_several_ids_is_one_group_with_all_ids():
    groups = cli.group_findings([finding("GHSA-aaaa"), finding("PYSEC-2024-1"), finding("GHSA-bbbb", cves=("CVE-2024-2",))])
    assert [[f["vulnerability_id"] for f in g] for g in groups] == [["GHSA-aaaa", "PYSEC-2024-1"], ["GHSA-bbbb"]]
    line = cli.describe_group(groups[0])
    assert line.count("CVE-2024-1") == 1
    assert "GHSA-aaaa" in line and "PYSEC-2024-1" in line
    assert line.startswith("requests 2.30.0: GHSA-aaaa, PYSEC-2024-1 (CVE-2024-1) -> AFFECTED")


def test_a_single_finding_is_described_exactly_as_before():
    one = finding("GHSA-aaaa")
    assert cli.describe_group([one]) == cli._describe(one)


def test_findings_that_differ_in_anything_that_matters_are_never_merged():
    a = finding("GHSA-aaaa")
    for change in ({"status": "UNKNOWN"}, {"action": "HUMAN_REVIEW"}, {"rule": "other"}, {"exploited": True, "exploited_via": "kev", "exploited_cve": "CVE-2024-1"},
                   {"version": "2.31.0"}, {"component": "other"}, {"purl": "pkg:pypi/other@2.30.0"}, {"ecosystem": "npm"}, {"exploited_known": False}, {"evidence_problem": ["CVE-2024-1"]}):
        groups = cli.group_findings([a, finding("PYSEC-1", **change)])
        assert len(groups) == 2, change


def test_findings_that_found_the_exploited_cve_in_different_ways_are_never_merged():
    a = finding("GHSA-a", exploited=True, exploited_via="kev", exploited_cve="CVE-2024-1", exploited_cve_matched_on="id", action="REPORT_CASE")
    b = finding("GHSA-b", exploited=True, exploited_via="kev", exploited_cve="CVE-2024-1", exploited_cve_matched_on="alias", action="REPORT_CASE")
    assert len(cli.group_findings([a, b])) == 2
    c = {**b, "vulnerability_id": "PYSEC-c"}
    assert len(cli.group_findings([b, c])) == 1  # the same way (both alias): one line


def test_a_field_added_to_findings_later_separates_them_by_default():
    assert len(cli.group_findings([finding("A"), finding("B", brand_new_field=1)])) == 2


def test_findings_with_a_missing_or_odd_cve_list_stay_single():
    for odd in (None, "CVE-1", 5, {}):
        a, b = finding("A"), finding("B")
        a["cve_ids"] = b["cve_ids"] = odd
        assert len(cli.group_findings([a, b])) == 2
    a = finding("A"); del a["cve_ids"]
    assert len(cli.group_findings([a])) == 1


def test_findings_without_a_cve_id_are_never_merged():
    groups = cli.group_findings([finding("GHSA-a", cves=()), finding("GHSA-b", cves=())])
    assert len(groups) == 2


def test_a_different_set_of_cve_ids_is_not_merged():
    groups = cli.group_findings([finding("GHSA-a", cves=("CVE-1", "CVE-2")), finding("GHSA-b", cves=("CVE-1",))])
    assert len(groups) == 2


def test_the_order_of_first_appearance_is_kept_and_nothing_is_lost():
    fs = [finding("A", cves=("CVE-1",)), finding("B", cves=("CVE-2",)), finding("C", cves=("CVE-1",)), finding("D", cves=("CVE-3",))]
    groups = cli.group_findings(fs)
    assert [g[0]["vulnerability_id"] for g in groups] == ["A", "B", "D"]
    assert sorted(f["vulnerability_id"] for g in groups for f in g) == ["A", "B", "C", "D"]


def test_grouping_does_not_change_the_findings_it_is_given():
    fs = [finding("A"), finding("B")]
    before = copy.deepcopy(fs)
    cli.group_findings(fs)
    assert fs == before


def test_a_long_id_list_stays_printable():
    line = cli.describe_group([finding(f"GHSA-{i:04d}") for i in range(50)])
    assert all(f"GHSA-{i:04d}" in line for i in range(50)) and len(line) < 2000


def test_in_a_real_run_the_screen_shows_it_once_but_the_run_record_keeps_every_finding(tmp_path, capsys, monkeypatch):
    real = matcher.evaluate

    def with_a_twin(components, feeds, evidence):
        result = real(components, feeds, evidence)
        twin = copy.deepcopy(next(f for f in result["findings"] if f["vulnerability_id"] == "GHSA-jfh8-c2jp-5v3q"))
        twin["vulnerability_id"] = "PYSEC-2021-TWIN"
        result["findings"].append(twin)
        return result

    monkeypatch.setattr(matcher, "evaluate", with_a_twin)
    run_cli(tmp_path)
    out = capsys.readouterr().out
    record = saved_run(tmp_path)
    twins = [f for f in record["result"]["findings"] if f["vulnerability_id"] in ("PYSEC-2021-TWIN", "GHSA-jfh8-c2jp-5v3q")]
    assert len(twins) == 2  # the run record still lists both, as the matcher made them
    shown = [l for l in out.splitlines() if "PYSEC-2021-TWIN" in l]
    assert len(shown) == 1 and "GHSA-jfh8-c2jp-5v3q" in shown[0]
    assert sum(1 for l in out.splitlines() if l.startswith("[") and "log4j-core 2.14.1" in l and "CVE-2021-44228) ->" in l) == 1
