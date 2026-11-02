"""Phase 3, piece 4: the fact checker. Plain code that rejects any draft with facts that are not in facts.json.

Pass 1 looks at the AI paragraph (only approved sentences are accepted). Pass 2 looks at the finished report.
"""

import time
from datetime import datetime, timezone

import pytest

from src import fact_checker as fc
from src import report_facts as rf
from src import report_template as rt
from src import summary_sentences as ss
from tests.test_report_facts import KEV_IDS, PRODUCT, evidence_finding, evidence_folder, kev_finding


def facts_for(finding=None, **kwargs):
    kwargs.setdefault("kev_ids", KEV_IDS)
    return rf.build_facts(PRODUCT, finding or kev_finding(), **kwargs)


def both(ids):
    return {lang: ss.compose(ids, lang) for lang in rf.LANGUAGES}


FALLBACK = both(ss.fallback_ids("kev"))
GOOD = both(["contains", "listed"])


def reports_for(facts, ids=None, source="code"):
    ids = ids or ss.fallback_ids(facts["exploited_via"])
    return {lang: rt.render_report(facts, lang, rt.fill_placeholders(ss.compose(ids, lang), facts), source) for lang in rf.LANGUAGES}


def with_text(lang, text):
    return {**GOOD, lang: text}


# ------------------------------------------------------------------ pass 1: the AI paragraph


def test_the_approved_sentences_pass_pass_1_and_the_checker_returns_its_own_text():
    result = fc.check_paragraphs(FALLBACK, "kev")
    assert result.ok and result.ids == ss.fallback_ids("kev") and result.texts == FALLBACK


def test_what_the_checker_returns_comes_from_the_table_not_from_the_ai_text():
    messy = {lang: "  " + text.replace(". ", ".\n\t ") + " \n" for lang, text in GOOD.items()}
    result = fc.check_paragraphs(messy, "kev")
    assert result.ok and result.texts == GOOD


def test_a_full_width_letter_is_normalised_but_a_look_alike_letter_is_refused():
    contains = {"en": ss.compose(["contains", "human_check"], "en"), "de": ss.compose(["contains", "human_check"], "de")}
    contains["en"] = contains["en"].replace("A human", chr(0xFF21) + " human")
    assert fc.check_paragraphs(contains, "kev").ok
    for look_alike in (chr(0x0410), chr(0x0391), "​"):  # Cyrillic A, Greek Alpha, zero-width space
        tricked = {**contains, "en": contains["en"].replace("A human", look_alike + " human").replace("contains", "con" + look_alike + "tains")}
        assert not fc.check_paragraphs(tricked, "kev").ok


@pytest.mark.parametrize("lang,text", [
    ("en", "The product is secure and no action is needed."),
    ("en", "Users are immune and the issue was remedied."),
    ("en", "Attackers stole customer data yesterday, tens of thousands of devices are hit."),
    ("en", "{product_name} is not-affected by {cve_id}."),
    ("en", "The early warning notification was reported to the authority and a person did review it."),
    ("en", "{cve_id} contains {product_name} and {component}."),
    ("en", "{product_name} contains {component} and {cve_id} is reported."),
    ("en", "{cve_id} is exploited in {product_name} and {component}."),
    ("en", "This draft is written by a human."),
    ("en", "{product_name} is responsible for the flaw. The product must be reported."),
    ("en", "Product X contains X."),
    ("en", "{component}fixed"),
    ("en", "El producto no esta afectado."),
    ("en", "Version IV. Since the first of march. Twentyfour hours. Millions of users. 3 March 2021 v3 2.x 9am."),
    ("en", "See bit.ly now. Visit https://evil.example/x"),
    ("de", "Das Produkt ist geschuetzt, keine Massnahmen noetig."),
    ("de", "Es ist nicht von {cve_id} betroffen."),
    ("de", "Die Frühwarnung wurde gemeldet. Die Behörde hat die Meldung."),
    ("de", "{product_name} ist für die Schwachstelle verantwortlich."),
    ("de", "Zweihundert Geraete, einundzwanzig Tage, Dreissig Prozent."),
    ("de", "Es gibt einen Sicherheitspatch. Das beheben wir."),
])
def test_false_claims_and_smuggled_facts_are_refused(lang, text):
    """Every payload the reviewers and the auditor found, plus the kinds of text a model could write on its own."""
    assert not fc.check_paragraphs(with_text(lang, text), "kev").ok, text
    assert not fc.check_draft(facts_for(), with_text(lang, text)).ok, text


def test_an_approved_sentence_with_one_word_changed_is_refused():
    changed = GOOD["en"].replace("contains the component", "contains the module")
    result = fc.check_paragraphs({**GOOD, "en": changed}, "kev")
    assert not result.ok and any("not an approved sentence" in p for p in result.problems)


def test_the_same_sentences_in_the_same_order_are_needed_in_german_and_english():
    result = fc.check_paragraphs({"en": ss.compose(["contains", "listed"], "en"), "de": ss.compose(["contains"], "de")}, "kev")
    assert not result.ok and any("same sentences" in p for p in result.problems)
    swapped = {"en": ss.compose(["contains", "listed"], "en"), "de": ss.compose(["listed", "contains"], "de")}
    assert not fc.check_paragraphs(swapped, "kev").ok


def test_the_reason_decides_which_sentences_may_be_used():
    kev_only = both(["contains", "kev"])
    evidence_only = both(["contains", "evidence"])
    assert fc.check_paragraphs(kev_only, "kev").ok and not fc.check_paragraphs(kev_only, "evidence_file").ok
    assert fc.check_paragraphs(evidence_only, "evidence_file").ok and not fc.check_paragraphs(evidence_only, "kev").ok


@pytest.mark.parametrize("paragraphs", [
    None, [], "x", {}, {"en": GOOD["en"]}, {"en": 5, "de": None}, {"en": b"x", "de": b"y"}, {"en": "", "de": ""},
    {"en": GOOD["en"], "de": GOOD["de"], "fr": "x"},
])
def test_odd_input_gives_a_fail_and_never_raises(paragraphs):
    assert not fc.check_paragraphs(paragraphs, "kev").ok
    assert not fc.check_draft(facts_for(), paragraphs).ok


def test_odd_facts_or_an_unknown_reason_give_a_fail_and_never_raise():
    for facts in (None, {}, "x", 5):
        assert not fc.check_draft(facts, GOOD).ok
    assert not fc.check_paragraphs(GOOD, "ai").ok
    assert not fc.check_paragraphs(GOOD, None).ok


def test_a_huge_paragraph_is_refused_quickly():
    for text in ("a-" * 100_000, "x" * 5_000_000, GOOD["en"] * 5_000):
        started = time.monotonic()
        result = fc.check_paragraphs(with_text("en", text), "kev")
        assert not result.ok and time.monotonic() - started < 1.0


# ------------------------------------------------------------------ pass 2: the finished report


def test_a_template_report_with_approved_sentences_passes_pass_2():
    facts = facts_for()
    assert fc.check_reports(facts, reports_for(facts)).ok


def test_pass_2_also_passes_for_human_evidence_and_with_an_awareness_time(tmp_path):
    facts = facts_for(evidence_finding(), evidence_dir=evidence_folder(tmp_path),
                      awareness=datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc))
    assert fc.check_reports(facts, reports_for(facts)).ok


def test_short_component_and_product_names_that_look_like_ordinary_words_do_not_confuse_pass_2():
    finding = kev_finding(component="name")
    facts = rf.build_facts({**PRODUCT, "product_name": "Name"}, finding, kev_ids=KEV_IDS)
    assert fc.check_draft(facts, FALLBACK).ok
    facts = rf.build_facts(PRODUCT, kev_finding(component="lib"), kev_ids=KEV_IDS)
    assert fc.check_draft(facts, FALLBACK).ok


def replace_in(reports, lang, old, new):
    assert old in reports[lang], old
    return {**reports, lang: reports[lang].replace(old, new)}


@pytest.mark.parametrize("old,new", [
    ("CVE-2021-44228", "CVE-2021-99999"),
    ("2.14.1", "2.15.0"),
    ("Musterfirma", "Musterfirma Evil GHSA-aaaa-bbbb-cccc"),
    ("Source: https://www.cisa.gov", "Source: https://evil.example"),
    ("DRAFT (NOT APPROVED, NOT SENT)", "FINAL (APPROVED)"),
    ("Nothing has been sent.", "Everything has been sent."),
])
def test_any_changed_value_or_wording_makes_the_report_differ_from_the_template(old, new):
    facts = facts_for()
    result = fc.check_reports(facts, replace_in(reports_for(facts), "en", old, new))
    assert not result.ok and any("template" in p or "summary line" in p for p in result.problems), result.problems


def test_a_changed_value_is_caught_in_german_too():
    facts = facts_for()
    assert not fc.check_reports(facts, replace_in(reports_for(facts), "de", "CVE-2021-44228", "CVE-2020-00001")).ok


@pytest.mark.parametrize("extra", [
    "The product is not affected.", "No action is needed.", "v3", "1st of March", "3 March 2021", "cve-2021-44228",
    "500 devices", "2026-10-20T09:41:00Z", "HTTPS://EVIL.EXAMPLE/x", "CWE-79", "ALAS2-2023-1234", "RHSA-2024:1234",
    "www.evil.example", "9am", "2.x", "20/10/2026", "October 20, 2026", "20 October 2026",
])
@pytest.mark.parametrize("where", ["after_footer", "inside_summary", "before_heading"])
def test_any_extra_text_anywhere_in_the_report_is_caught(extra, where):
    facts = facts_for()
    reports = reports_for(facts)
    text = reports["en"]
    if where == "after_footer":
        text += extra + "\n"
    elif where == "inside_summary":
        text = text.replace("Summary:\n", f"Summary:\n{extra} ", 1)
    else:
        text = extra + "\n" + text
    assert not fc.check_reports(facts, {**reports, "en": text}).ok


@pytest.mark.parametrize("lang", ["de", "en"])
@pytest.mark.parametrize("field", rt.FIELD_LINES)
def test_a_missing_required_field_is_caught_in_each_language(lang, field):
    facts = facts_for()
    reports = reports_for(facts)
    prefix = rt.LABELS[lang][field] + ":"
    lines = reports[lang].split("\n")
    kept = [line for line in lines if not line.startswith(prefix)]
    assert len(kept) == len(lines) - 1
    assert not fc.check_reports(facts, {**reports, lang: "\n".join(kept)}).ok


def test_a_forged_second_deadline_line_is_caught():
    facts = facts_for()
    reports = reports_for(facts)
    forged = f"{rt.LABELS['en']['deadline']}: 31 Dec 2030"
    status = rt.LABELS["en"]["status"]
    assert not fc.check_reports(facts, replace_in(reports, "en", f"\n{status}:", f"\n{forged}\n{status}:")).ok


def test_a_lie_in_the_summary_line_is_caught():
    facts = facts_for()
    reports = reports_for(facts)
    filled = rt.fill_placeholders(ss.compose(ss.fallback_ids("kev"), "en"), facts)
    result = fc.check_reports(facts, replace_in(reports, "en", filled, "The product is secure."))
    assert not result.ok and any("summary line" in p for p in result.problems)


def test_a_changed_word_in_the_summary_line_is_caught():
    facts = facts_for()
    reports = reports_for(facts)
    result = fc.check_reports(facts, replace_in(reports, "de", "Ein Mensch muss jede Aussage prüfen, bevor etwas gemeldet wird.", "Ein Mensch muss jede Aussage prüfen, bevor etwas gesendet wird."))
    assert not result.ok and any("summary line" in p for p in result.problems)


def test_a_summary_sentence_that_does_not_fit_the_reason_is_caught():
    facts = facts_for()  # reason: KEV
    reports = reports_for(facts)
    evidence_sentence = rt.fill_placeholders(ss.compose(["evidence"], "en"), facts)
    kev_sentence = rt.fill_placeholders(ss.compose(["kev"], "en"), facts)
    assert not fc.check_reports(facts, replace_in(reports, "en", kev_sentence, evidence_sentence)).ok


def test_leftover_braces_look_alike_letters_and_control_characters_are_caught():
    facts = facts_for()
    reports = reports_for(facts)
    for bad in ("{cve_id}", chr(0x0430), chr(0x200B), "\t", "\x1b[2J", chr(0xFB01)):
        tampered = {**reports, "en": reports["en"].replace("Summary:\n", f"Summary:\n{bad}")}
        assert not fc.check_reports(facts, tampered).ok, repr(bad)


def test_a_missing_language_or_an_empty_or_odd_report_is_caught_and_never_raises():
    facts = facts_for()
    reports = reports_for(facts)
    for odd in (None, [], "x", {"en": reports["en"]}, {**reports, "de": ""}, {**reports, "de": None}, {"en": b"x", "de": b"y"},
                {"en": 5, "de": None}, {"en": "", "de": ""}):
        assert not fc.check_reports(facts, odd).ok


def test_a_huge_report_is_refused_quickly():
    facts = facts_for()
    started = time.monotonic()
    assert not fc.check_reports(facts, {**reports_for(facts), "en": "a-" * 500_000}).ok
    assert time.monotonic() - started < 1.0


def test_edited_facts_make_the_check_fail_instead_of_trusting_them():
    facts = facts_for()
    reports = reports_for(facts)
    facts["title"] = {"en": "Harmless", "de": "Harmlos"}
    result = fc.check_reports(facts, reports)
    assert not result.ok and any("facts" in p for p in result.problems)


def test_times_at_the_end_of_the_calendar_give_a_fail_not_an_exception():
    facts = facts_for()
    facts["awareness_time_utc"] = "9999-12-30T23:30:00+00:00"
    facts["deadline_utc"] = "9999-12-31T23:30:00+00:00"
    assert not fc.check_draft(facts, GOOD).ok
    assert not fc.check_reports(facts, {"de": "x", "en": "y"}).ok


# ------------------------------------------------------------------ both passes together


def test_check_draft_runs_both_passes_and_returns_the_finished_reports():
    facts = facts_for()
    result = fc.check_draft(facts, GOOD)
    assert result.ok and result.status == "PASS" and set(result.reports) == {"de", "en"}
    assert "CVE-2021-44228" in result.reports["en"] and "{" not in result.reports["en"]
    assert "The component log4j-core is listed with the vulnerability CVE-2021-44228." in result.reports["en"]


def test_check_draft_fails_when_pass_1_fails_and_gives_no_reports():
    result = fc.check_draft(facts_for(), with_text("en", "{product_name} is safe."))
    assert not result.ok and result.status == "FAIL" and result.reports is None


def test_a_paragraph_that_becomes_too_long_once_the_placeholders_are_filled_is_a_fail():
    facts = rf.build_facts(PRODUCT, kev_finding(component="a" * 200), kev_ids={"CVE-2021-44228"})
    result = fc.check_draft(facts, GOOD)
    assert result.ok  # 200 characters per placeholder is still fine here
    long_name = "a" * 256
    facts = rf.build_facts({**PRODUCT, "product_name": "P" * 250, "manufacturer": "M" * 250}, kev_finding(component=long_name),
                           kev_ids={"CVE-2021-44228"})
    result = fc.check_draft(facts, both(["contains", "listed", "kev", "human_check"]))
    assert not result.ok and any("could not be written" in p for p in result.problems)


def test_the_result_can_be_saved_as_plain_json():
    import json
    saved = json.loads(json.dumps(fc.check_draft(facts_for(), GOOD).as_dict()))
    assert saved == {"status": "PASS", "problems": []}


@pytest.mark.parametrize("name", ["Acme  Gate", "Acme   Gate ", "Acme Gate  X1", "A  B  C"])
def test_blanks_in_a_name_do_not_break_the_fixed_fallback_or_a_real_report(name):
    """A product name may contain two blanks in a row; the finished line then has them too, and must still be accepted."""
    facts = rf.build_facts({**PRODUCT, "product_name": name, "manufacturer": name}, kev_finding(), kev_ids=KEV_IDS)
    result = fc.check_draft(facts, FALLBACK)
    assert result.ok, result.problems
    assert fc.check_reports(facts, result.reports).ok
