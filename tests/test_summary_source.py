"""Phase 3, piece 5: the report says who wrote the summary paragraph (an AI checked by code, or fixed wording by code)."""

import pytest

from src import fact_checker as fc
from src import report_facts as rf
from src import report_template as rt
from tests.test_fact_checker import GOOD
from tests.test_report_facts import KEV_IDS, PRODUCT, kev_finding


def facts():
    return rf.build_facts(PRODUCT, kev_finding(), kev_ids=KEV_IDS)


def reports_with(source):
    f = facts()
    return f, {lang: rt.render_report(f, lang, rt.fill_placeholders(GOOD[lang], f), source) for lang in rf.LANGUAGES}


def test_the_default_says_fixed_wording_by_code():
    f = facts()
    text = rt.render_report(f, "en", rt.fill_placeholders(GOOD["en"], f))
    assert rt.LABELS["en"]["source_code"] in text.split("\n") and rt.LABELS["en"]["source_ai"] not in text


@pytest.mark.parametrize("lang", ["de", "en"])
def test_the_source_line_follows_the_paragraph_directly(lang):
    for source, key in (("ai", "source_ai"), ("code", "source_code")):
        f, reports = reports_with(source)
        lines = reports[lang].split("\n")
        at = lines.index(rt.LABELS[lang]["summary"] + ":")
        assert lines[at + 2] == rt.LABELS[lang][key]


def test_an_unknown_source_is_refused():
    f = facts()
    for bad in ("human", None, "AI", ""):
        with pytest.raises(rf.FactsError):
            rt.render_report(f, "en", "x", bad)


def test_pass_2_accepts_the_matching_source_and_refuses_the_wrong_one():
    for source, other in (("ai", "code"), ("code", "ai")):
        f, reports = reports_with(source)
        assert fc.check_reports(f, reports, source).ok
        result = fc.check_reports(f, reports, other)
        assert not result.ok and any("summary source" in p for p in result.problems)
        assert fc.check_reports(f, reports).ok  # without a stated source either honest line is fine


def test_pass_2_refuses_a_report_with_no_source_line_or_with_both():
    f, reports = reports_with("code")
    en = reports["en"]
    without = en.replace(rt.LABELS["en"]["source_code"] + "\n", "")
    both = en.replace(rt.LABELS["en"]["source_code"], rt.LABELS["en"]["source_code"] + "\n" + rt.LABELS["en"]["source_ai"])
    for tampered in (without, both):
        result = fc.check_reports(f, {**reports, "en": tampered})
        assert not result.ok and any("summary source" in p for p in result.problems)


def test_check_draft_writes_the_requested_source_line():
    f = facts()
    result = fc.check_draft(f, GOOD, "ai")
    assert result.ok and rt.LABELS["en"]["source_ai"] in result.reports["en"]
    assert fc.check_draft(f, GOOD).reports["en"].count(rt.LABELS["en"]["source_code"]) == 1
