"""Phase 3, piece 4: every bypass found by the code reviewer and the security auditor must now be refused.

The checker is a deny-list PLUS a small approved word list. A false claim written in words nobody thought of
(for example "secure", "immune", "solved") is refused because the word is not on the approved list.
"""

import time

import pytest

from src import fact_checker as fc
from src import report_facts as rf
from src import report_template as rt
from tests.test_fact_checker import GOOD, facts_for, reports_for, with_text

CLAIMS_EN = [
    "The product is secure and no action is needed.",
    "Users are immune and the issue was remedied.",
    "Attackers stole customer data yesterday, tens of thousands of devices are hit.",
    "The problem is solved, {product_name} is not-affected by {cve_id}.",
    "{product_name} is not really affected by {cve_id}.",
    "{product_name} is no longer affected.",
    "{product_name} is not vulnerable.",
    "It was a false alarm.",
    "It is no longer exploited.",
    "It does not need to be reported.",
    "Isn't impacted.",
    "El producto no esta afectado.",
    "Le produit n'est pas touche.",
    "Millions of users are hit.",
    "Hundreds of devices are hit.",
    "twentyfour hours remain",
    "Roman numeral version IV is hit.",
    "Since the first of march it is known.",
    "Known since OCTOBER.",
    "See bit.ly now.",
    "All affected versions are hit.",
    "Every version is hit.",
    "{component}fixed",
    "received a bugfix",
    "received a hotfix",
    "It is unsafe.",
    "Safety is not an issue.",
]
CLAIMS_DE = [
    "Das Produkt ist geschuetzt, keine Massnahmen noetig.",
    "Es ist nicht von {cve_id} betroffen.",
    "Zweihundert Geraete sind betroffen.",
    "einundzwanzig Geraete",
    "Dreissig Tage",
    "Sämtliche Versionen sind betroffen.",
    "Es gibt einen Sicherheitspatch.",
    "Das beheben wir.",
    "Behebungen folgen.",
    "Zehn Prozent sind betroffen.",
    "Das Problem ist gelöst.",
    "Das Produkt ist unsicher.",
    "Bekannt seit OKTOBER.",
    "Das Produkt ist sicher.",
]


@pytest.mark.parametrize("text", CLAIMS_EN)
def test_false_claims_and_smuggled_facts_in_the_english_paragraph_are_refused(text):
    assert not fc.check_paragraphs(with_text("en", text)).ok, text
    assert not fc.check_draft(facts_for(), with_text("en", text)).ok, text


@pytest.mark.parametrize("text", CLAIMS_DE)
def test_false_claims_and_smuggled_facts_in_the_german_paragraph_are_refused(text):
    assert not fc.check_paragraphs(with_text("de", text)).ok, text


def test_a_german_sentence_in_the_english_slot_and_the_other_way_round_is_refused():
    assert not fc.check_paragraphs(with_text("en", "Das Produkt enthält die Komponente {component}. {product_name} {cve_id}")).ok
    assert not fc.check_paragraphs(with_text("de", "{product_name} contains the component {component}. {cve_id}")).ok


def test_the_message_names_the_words_that_are_not_on_the_approved_list():
    result = fc.check_paragraphs(with_text("en", "{product_name} is immune."))
    assert any("not on the approved list" in p and "immune" in p for p in result.problems)


def test_every_word_of_the_fixed_fallback_texts_is_on_the_approved_list():
    from src import report_writer as rw
    assert fc.check_paragraphs(rw.FALLBACK).ok


def test_may_at_the_start_of_a_sentence_is_fine_because_the_month_is_not_a_word_on_the_list():
    assert fc.check_paragraphs({"en": "May contain {component}.", "de": "Kann {component} enthalten."}).ok


# ------------------------------------------------------------------ pass 2 on a finished report, called on its own


def with_extra(lang, text, where="end"):
    facts = facts_for()
    reports = reports_for(facts)
    if where == "end":
        reports[lang] = reports[lang] + text + "\n"
    else:
        reports[lang] = reports[lang].replace("Summary:\n", f"Summary:\n{text}\n", 1)
    return facts, reports


@pytest.mark.parametrize("extra", [
    "The product is not affected.", "No action is needed.", "v3", "1st of March", "3 March 2021", "cve-2021-44228",
    "500 devices", "2026-10-20T09:41:00Z", "HTTPS://EVIL.EXAMPLE/x", "CWE-79", "ALAS2-2023-1234", "RHSA-2024:1234",
    "www.evil.example", "9am", "2.x", "20/10/2026", "October 20, 2026", "20 October 2026",
])
def test_any_extra_line_after_the_footer_is_caught(extra):
    facts, reports = with_extra("en", extra)
    result = fc.check_reports(facts, reports)
    assert not result.ok and any("template" in p or "not in the facts" in p for p in result.problems), (extra, result.problems)


@pytest.mark.parametrize("extra", ["HTTPS://EVIL.EXAMPLE/x", "ISO 2026-10-20T09:41:00Z", "v3", "2.x", "9am", "CWE-79"])
def test_these_facts_like_tokens_are_found_by_the_extractor_even_inside_the_summary_line(extra):
    facts, reports = with_extra("en", extra, where="summary")
    result = fc.check_reports(facts, reports)
    assert not result.ok
    assert any("not in the facts" in p for p in result.problems), (extra, result.problems)


def test_a_lie_in_the_summary_line_is_caught_even_when_check_reports_is_called_alone():
    facts = facts_for()
    reports = reports_for(facts)
    lie = "The product is secure."
    reports["en"] = reports["en"].replace(rt.fill_placeholders(GOOD["en"], facts), lie)
    result = fc.check_reports(facts, reports)
    assert not result.ok and any("summary paragraph" in p for p in result.problems)


def test_a_forbidden_word_in_an_edited_summary_line_is_caught():
    facts = facts_for()
    reports = reports_for(facts)
    reports["de"] = reports["de"].replace(rt.fill_placeholders(GOOD["de"], facts), "Das Produkt ist nicht betroffen.")
    result = fc.check_reports(facts, reports)
    assert not result.ok and any("forbidden" in p for p in result.problems)


def test_a_changed_heading_or_a_removed_line_makes_the_report_differ_from_the_template():
    facts = facts_for()
    reports = reports_for(facts)
    changed = {**reports, "en": reports["en"].replace("DRAFT (NOT APPROVED, NOT SENT)", "FINAL (APPROVED)")}
    result = fc.check_reports(facts, changed)
    assert not result.ok and any("template" in p for p in result.problems)


# ------------------------------------------------------------------ speed and crashes: always a FAIL, never an exception


def test_a_huge_paragraph_is_refused_quickly():
    for text in ("a-" * 100_000, "x" * 5_000_000, "{component} " * 100_000):
        started = time.monotonic()
        result = fc.check_paragraphs(with_text("en", text))
        assert not result.ok and time.monotonic() - started < 1.0


def test_a_huge_report_is_refused_quickly():
    facts = facts_for()
    reports = reports_for(facts)
    started = time.monotonic()
    result = fc.check_reports(facts, {**reports, "en": "a-" * 500_000})
    assert not result.ok and time.monotonic() - started < 1.0


def test_times_at_the_end_of_the_calendar_give_a_fail_not_an_exception():
    facts = facts_for()
    facts["awareness_time_utc"] = "9999-12-30T23:30:00+00:00"
    facts["deadline_utc"] = "9999-12-31T23:30:00+00:00"
    assert not fc.check_draft(facts, GOOD).ok
    assert not fc.check_reports(facts, {"de": "x", "en": "y"}).ok


@pytest.mark.parametrize("facts,paragraphs", [(None, GOOD), ({}, GOOD), ("x", GOOD), (facts_for(), None), (facts_for(), []),
                                              (facts_for(), {"en": 5, "de": None}), (facts_for(), {"en": GOOD["en"]})])
def test_odd_input_gives_a_fail_and_never_raises(facts, paragraphs):
    assert not fc.check_draft(facts, paragraphs).ok


@pytest.mark.parametrize("reports", [None, [], "x", {"en": 5, "de": None}, {"en": "", "de": ""}, {"en": b"x", "de": b"y"}])
def test_odd_reports_give_a_fail_and_never_raise(reports):
    assert not fc.check_reports(facts_for(), reports).ok


def test_a_paragraph_that_becomes_too_long_once_the_placeholders_are_filled_is_a_fail():
    facts = rf.build_facts({**__import__("tests.test_report_facts", fromlist=["PRODUCT"]).PRODUCT}, __import__("tests.test_report_facts", fromlist=["kev_finding"]).kev_finding(component="a" * 200),
                           kev_ids={"CVE-2021-44228"})
    paragraph = "{component} " * 10
    result = fc.check_draft(facts, {"en": paragraph, "de": paragraph})
    assert not result.ok and any("could not be written" in p for p in result.problems)


def test_a_paragraph_that_starts_like_a_label_is_refused():
    assert not fc.check_paragraphs(with_text("de", "Quelle: {component}")).ok
    assert not fc.check_paragraphs(with_text("en", "Product: {component}")).ok
