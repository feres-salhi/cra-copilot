"""Phase 3, piece 4: the fact checker. Plain code that rejects any draft with facts that are not in facts.json.

Pass 1 looks at the AI paragraph alone. Pass 2 looks at the finished report after the placeholders were filled.
"""

import pytest

from src import fact_checker as fc
from src import report_facts as rf
from src import report_template as rt
from tests.test_report_facts import EVIDENCE, KEV_IDS, PRODUCT, evidence_finding, evidence_folder, kev_finding

GOOD = {
    "en": "{product_name} contains the component {component}. It is listed with {cve_id}, which public sources list as exploited.",
    "de": "{product_name} enthält die Komponente {component}. Sie ist mit {cve_id} gelistet, die in öffentlichen Quellen als ausgenutzt geführt wird.",
}


def facts_for(finding=None, **kwargs):
    kwargs.setdefault("kev_ids", KEV_IDS)
    return rf.build_facts(PRODUCT, finding or kev_finding(), **kwargs)


def reports_for(facts, paragraphs=GOOD):
    return {lang: rt.render_report(facts, lang, rt.fill_placeholders(paragraphs[lang], facts)) for lang in rf.LANGUAGES}


def with_text(lang, text):
    return {**GOOD, lang: text}


# ------------------------------------------------------------------ pass 1: the AI paragraph


def test_a_plain_paragraph_passes_pass_1():
    result = fc.check_paragraphs(GOOD)
    assert result.ok and result.problems == []


@pytest.mark.parametrize("lang,text", [
    ("en", "{product_name} has {component} version 2."),
    ("en", "Since 2021 {cve_id} is known."),
    ("en", "{product_name} has " + chr(0xff12) + " parts."),  # a full-width digit: normalised to 2, then refused
    ("en", "{product_name} has " + chr(0x663) + " parts."),  # an Arabic-Indic digit
    ("de", "{product_name} hat 3 Teile."),
])
def test_any_digit_is_refused(lang, text):
    result = fc.check_paragraphs(with_text(lang, text))
    assert not result.ok and any("digit" in p for p in result.problems)


@pytest.mark.parametrize("text", [
    "{product_name} contains the component {component}. It is not affected.",
    "{product_name} is NOT  affected by {cve_id}.",
    "{product_name} is unaffected.",
    "The issue is fixed in {component}.",
    "A fix exists for {component}.",
    "A patch was released for {component}.",
    "{component} was patched.",
    "This is a critical problem in {component}.",
    "{component} has a high CVSS rating.",
    "{component} is safe to use.",
    "{product_name} is safely configured.",
    "All versions of {component} are hit.",
    "Two components are hit.",
    "{component} was resolved.",
    "The risk is mitigated.",
    "This is harmless.",
    "There is no risk for {product_name}.",
    "The problem started in October.",
])
def test_forbidden_words_in_english_are_refused(text):
    result = fc.check_paragraphs(with_text("en", text))
    assert not result.ok and any("forbidden" in p for p in result.problems), text


@pytest.mark.parametrize("text", [
    "{product_name} ist nicht betroffen.",
    "{product_name} ist NICHT   betroffen.",
    "Das Problem wurde behoben.",
    "Es gibt eine Behebung.",
    "{component} wurde gepatcht.",
    "Ein Patch liegt vor.",
    "Das ist kritisch.",
    "{component} hat einen hohen CVSS-Wert.",
    "{product_name} ist sicher.",
    "Der Betrieb ist nicht sicher.",
    "Alle Versionen sind betroffen.",
    "Zwei Komponenten sind betroffen.",
    "Das Problem ist harmlos.",
    "Es besteht kein Risiko.",
    "Das Problem wurde gelöst.",
    "Bekannt seit Oktober.",
    "Bekannt seit März.",
])
def test_forbidden_words_in_german_are_refused(text):
    result = fc.check_paragraphs(with_text("de", text))
    assert not result.ok and any("forbidden" in p for p in result.problems), text


def test_a_percent_sign_is_refused():
    result = fc.check_paragraphs(with_text("en", "{component} affects 5% of users"))
    assert not result.ok


def test_plain_neutral_words_from_the_approved_list_are_allowed():
    text = {"en": "{product_name} may contain {component}. A human must check this.",
            "de": "{product_name} kann {component} enthalten. Ein Mensch muss dies prüfen."}
    text["de"] = text["de"].replace("dies prüfen", "diese Aussage prüfen")
    result = fc.check_paragraphs(text)
    assert result.ok, result.problems


@pytest.mark.parametrize("trick", [
    "{component} is " + chr(0xff53) + "" + chr(0xff41) + "" + chr(0xff46) + "" + chr(0xff45) + ".",  # full-width "safe": normalised, then caught as a forbidden word
    "The " + chr(0xfb01) + "xed version of {component}.",  # the ligature fi: normalised to "fixed"
    "{component} is sa" + chr(0x200b) + "fe.",  # a zero-width space inside a word
    "{component} is s" + chr(0x430) + "fe.",  # Cyrillic a inside "safe"
    "{product_name} h" + chr(0x435) + "lps.",  # Cyrillic e
    "{component} is s" + chr(0x3bf) + "me.",  # Greek omicron
    "{component} is " + chr(0x202e) + "evil.",  # a right-to-left override
])
def test_look_alike_and_invisible_characters_are_refused_or_normalised_into_a_caught_word(trick):
    assert not fc.check_paragraphs(with_text("en", trick)).ok


def test_the_normalised_text_is_returned_and_is_what_gets_used():
    result = fc.check_paragraphs({"en": "{product_name} contains " + chr(0xff21) + " component.", "de": "{product_name} enthält eine Komponente."})
    assert result.ok and result.texts["en"] == "{product_name} contains A component."


@pytest.mark.parametrize("text", [
    "{unknown} is here", "{version} is here", "{product_name", "product_name}", "{{cve_id}}", "{}", "{ cve_id }",
    "{cve_id}}", "{PRODUCT_NAME}", "{cve_id!r}", "{cve_id:>5}", "{0}",
])
def test_only_the_three_allowed_placeholders_are_accepted(text):
    result = fc.check_paragraphs(with_text("en", text))
    assert not result.ok and any("placeholder" in p or "brace" in p for p in result.problems), text


def test_the_placeholder_set_must_be_the_same_in_german_and_english():
    result = fc.check_paragraphs({"en": "{product_name} and {component}.", "de": "{product_name} und {cve_id}."})
    assert not result.ok and any("same placeholders" in p for p in result.problems)
    assert fc.check_paragraphs({"en": "{component} and {product_name}.", "de": "{product_name} und {component}."}).ok


@pytest.mark.parametrize("text", [
    "line one\nline two", "tab\there", "", "   ", "x" * 1001,
    "<script>alert</script>", "see `code`", "[a](b)", "a | b", "*bold*", "# heading", "back\\slash", "a_b", "a=b",
    "see http://evil.example now", "see www.evil.example now", "mail me at evil.com", "x@y", "a/b",
])
def test_markup_links_line_breaks_and_empty_text_are_refused(text):
    assert not fc.check_paragraphs(with_text("en", text)).ok, repr(text)


def test_non_text_is_refused_without_a_crash():
    for bad in (None, 5, ["x"], b"bytes"):
        assert not fc.check_paragraphs({"en": bad, "de": GOOD["de"]}).ok
    assert not fc.check_paragraphs({"en": GOOD["en"]}).ok  # German missing
    assert not fc.check_paragraphs(None).ok


# ------------------------------------------------------------------ pass 2: the finished report


def test_a_template_report_with_a_good_paragraph_passes_pass_2():
    facts = facts_for()
    result = fc.check_reports(facts, reports_for(facts))
    assert result.ok, result.problems


def test_pass_2_also_passes_for_human_evidence_and_with_an_awareness_time(tmp_path):
    from datetime import datetime, timezone
    facts = facts_for(evidence_finding(), evidence_dir=evidence_folder(tmp_path),
                      awareness=datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc))
    assert fc.check_reports(facts, reports_for(facts)).ok


def replace_in(reports, lang, old, new):
    assert old in reports[lang], old
    return {**reports, lang: reports[lang].replace(old, new)}


@pytest.mark.parametrize("old,new,what", [
    ("CVE-2021-44228", "CVE-2021-99999", "CVE-2021-99999"),
    ("2.14.1", "2.15.0", "2.15.0"),
    ("Musterfirma", "Musterfirma Evil GHSA-aaaa-bbbb-cccc", "GHSA-aaaa-bbbb-cccc"),
    ("Source: https://www.cisa.gov", "Source: https://evil.example", "https://evil.example"),
])
def test_an_invented_id_version_or_link_is_caught_in_english(old, new, what):
    facts = facts_for()
    result = fc.check_reports(facts, replace_in(reports_for(facts), "en", old, new))
    assert not result.ok and any(what in p for p in result.problems), result.problems


def test_an_invented_id_is_caught_in_german_too():
    facts = facts_for()
    result = fc.check_reports(facts, replace_in(reports_for(facts), "de", "CVE-2021-44228", "CVE-2020-00001"))
    assert not result.ok and any("CVE-2020-00001" in p for p in result.problems)


@pytest.mark.parametrize("extra", [
    "Seen on 2026-10-20.", "Seen on 20.10.2026.", "Seen on 20 Oct 2026.", "Fixed at 09:41.", "Use 3.0.1 now.",
    "See https://evil.example/x.", "Related GHSA-xxxx-yyyy-zzzz.", "Also PYSEC-2023-74.",
])
def test_an_extra_date_time_version_link_or_id_anywhere_in_the_report_is_caught(extra):
    facts = facts_for()
    reports = reports_for(facts)
    reports["en"] = reports["en"].replace("Summary:\n", f"Summary:\n{extra} ")
    result = fc.check_reports(facts, reports)
    assert not result.ok and any("not in the facts" in p for p in result.problems), (extra, result.problems)


def test_a_date_that_is_in_the_facts_is_fine(tmp_path):
    facts = facts_for(evidence_finding(), evidence_dir=evidence_folder(tmp_path))
    reports = reports_for(facts)
    assert "20 Oct 2026" in reports["en"]
    assert fc.check_reports(facts, reports).ok


@pytest.mark.parametrize("lang", ["de", "en"])
@pytest.mark.parametrize("field", rt.FIELD_LINES)
def test_a_missing_required_field_is_caught_in_each_language(lang, field):
    facts = facts_for()
    reports = reports_for(facts)
    prefix = rt.LABELS[lang][field] + ":"
    lines = reports[lang].split(chr(10))
    kept = [line for line in lines if not line.startswith(prefix)]
    assert len(kept) == len(lines) - 1
    result = fc.check_reports(facts, {**reports, lang: chr(10).join(kept)})
    assert not result.ok and any("required field" in p for p in result.problems), result.problems


def test_a_forged_second_deadline_line_is_caught():
    facts = facts_for()
    reports = reports_for(facts)
    forged = f"{rt.LABELS['en']['deadline']}: 31 Dec 2030"
    reports["en"] = reports["en"].replace(f"\n{rt.LABELS['en']['status']}:", f"\n{forged}\n{rt.LABELS['en']['status']}:")
    result = fc.check_reports(facts, reports)
    assert not result.ok and any("more than once" in p for p in result.problems)


def test_a_missing_language_or_empty_report_is_caught():
    facts = facts_for()
    reports = reports_for(facts)
    assert not fc.check_reports(facts, {"en": reports["en"]}).ok
    assert not fc.check_reports(facts, {**reports, "de": ""}).ok
    assert not fc.check_reports(facts, {**reports, "de": None}).ok
    assert not fc.check_reports(facts, None).ok


def test_leftover_braces_are_caught_in_the_finished_report():
    facts = facts_for()
    reports = reports_for(facts)
    reports["en"] = reports["en"].replace("Summary:\n", "Summary:\n{cve_id} ")
    result = fc.check_reports(facts, reports)
    assert not result.ok and any("brace" in p for p in result.problems)


def test_look_alike_letters_and_control_characters_in_the_finished_report_are_caught():
    facts = facts_for()
    reports = reports_for(facts)
    for bad in ("" + chr(0x430) + "", "" + chr(0x200b) + "", "\t", "\x1b[2J", "" + chr(0xfb01) + ""):
        tampered = {**reports, "en": reports["en"].replace("Summary:\n", f"Summary:\n{bad}")}
        assert not fc.check_reports(facts, tampered).ok, repr(bad)


def test_a_report_without_the_fixed_status_sentence_or_footer_is_caught():
    facts = facts_for()
    reports = reports_for(facts)
    no_status = {**reports, "en": reports["en"].replace(rt.status_sentence(facts, "en"), "All fine.")}
    assert not fc.check_reports(facts, no_status).ok
    no_footer = {**reports, "de": reports["de"].replace(rt.LABELS["de"]["footer"], "")}
    assert not fc.check_reports(facts, no_footer).ok


def test_edited_facts_make_the_check_fail_instead_of_trusting_them():
    facts = facts_for()
    reports = reports_for(facts)
    facts["title"] = {"en": "Harmless", "de": "Harmlos"}
    result = fc.check_reports(facts, reports)
    assert not result.ok and any("facts" in p for p in result.problems)


# ------------------------------------------------------------------ both passes together


def test_check_draft_runs_both_passes_and_returns_the_finished_reports():
    facts = facts_for()
    result = fc.check_draft(facts, GOOD)
    assert result.ok and result.status == "PASS" and set(result.reports) == {"de", "en"}
    assert "CVE-2021-44228" in result.reports["en"] and "{" not in result.reports["en"]


def test_check_draft_uses_the_normalised_paragraph():
    facts = facts_for()
    result = fc.check_draft(facts, {"en": "{product_name} contains " + chr(0xff21) + " component.", "de": "{product_name} enthält eine Komponente."})
    assert result.ok and "contains A component." in result.reports["en"]


def test_check_draft_fails_when_pass_1_fails_and_gives_no_reports():
    facts = facts_for()
    result = fc.check_draft(facts, with_text("en", "{product_name} is safe."))
    assert not result.ok and result.status == "FAIL" and result.reports is None
    assert any("forbidden" in p for p in result.problems)


def test_the_result_can_be_saved_as_plain_json():
    import json
    result = fc.check_draft(facts_for(), GOOD)
    saved = json.loads(json.dumps(result.as_dict()))
    assert saved["status"] == "PASS" and saved["problems"] == []
