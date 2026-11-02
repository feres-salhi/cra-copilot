"""Improvement 6: "a human should confirm" only for CVE links that rest on "upstream" (less alarm fatigue).
That the link came from an alias stays recorded in the run record and in the report assessment line."""
import json

import pytest

from src import cli, report_template as rt
from tests.test_cli_run import run_cli, saved_run
from src import report_facts as rf
from tests.test_report_facts import KEV_IDS, PRODUCT, kev_finding


def exploited(matched_on):
    return {
        "component": "log4j-core", "version": "2.14.1", "vulnerability_id": "GHSA-x", "cve_ids": ["CVE-2021-44228"],
        "status": "AFFECTED", "rule": "osv_exact_version_list", "exploited": True, "exploited_via": "kev",
        "exploited_cve": "CVE-2021-44228", "exploited_cve_matched_on": matched_on, "evidence": None,
        "evidence_problem": [], "exploited_known": True,
    }


def test_the_normal_alias_link_has_no_confirm_note_but_still_says_where_the_link_came_from():
    text = cli._describe(exploited("alias"))
    assert "should confirm" not in text
    assert "linked through an alias" in text  # still visible, just not an alarm


def test_a_direct_id_link_has_no_note():
    text = cli._describe(exploited("id"))
    assert "should confirm" not in text and "linked through" not in text


def test_an_upstream_link_still_asks_a_human_to_confirm():
    text = cli._describe(exploited("upstream"))
    assert "linked through an upstream" in text and "a human should confirm" in text


@pytest.mark.parametrize("odd", [None, "", "weird", 5])
def test_an_unexpected_link_kind_still_asks_a_human_to_confirm(odd):
    assert "a human should confirm" in cli._describe(exploited(odd))


def test_a_group_line_follows_the_same_rule():
    group = cli.group_findings([exploited("upstream"), {**exploited("upstream"), "vulnerability_id": "PYSEC-1"}])
    assert "a human should confirm" in cli.describe_group(group[0])
    group = cli.group_findings([exploited("alias"), {**exploited("alias"), "vulnerability_id": "PYSEC-1"}])
    assert "should confirm" not in cli.describe_group(group[0])


def test_the_demo_run_has_no_confirm_note_for_alias_links_but_the_record_keeps_them(tmp_path, capsys):
    run_cli(tmp_path)
    out = capsys.readouterr().out
    record = saved_run(tmp_path)
    matched = {f["exploited_cve_matched_on"] for f in record["result"]["findings"] if f["exploited"]}
    assert "alias" in matched  # recorded in the run record, unchanged
    assert "linked through an alias" in out and "a human should confirm" not in out


@pytest.mark.parametrize("lang, phrase", [("en", "rests on an alias"), ("de", "beruht auf einem Alias")])
def test_the_report_assessment_line_still_mentions_the_alias(lang, phrase):
    facts = rf.build_facts(PRODUCT, kev_finding(exploited_cve_matched_on="alias"), kev_ids=KEV_IDS)
    assert facts["cve_matched_on"] == "alias"
    assert phrase in rt.status_sentence(facts, lang)
