"""Phase 3, piece 3: the fixed German + English early-warning template, written by code (not by the AI)."""

import re
from datetime import datetime, timezone

import pytest

from src import report_facts as rf
from src import report_template as rt
from tests.test_report_facts import EVIDENCE, KEV_IDS, PRODUCT, evidence_finding, evidence_folder, kev_finding

PARAGRAPH = {"en": "{product_name} uses {component}. See {cve_id}.", "de": "{product_name} nutzt {component}. Siehe {cve_id}."}


def make(finding=None, **kwargs):
    kwargs.setdefault("kev_ids", KEV_IDS)
    facts = rf.build_facts(PRODUCT, finding or kev_finding(), **kwargs)
    filled = {lang: rt.fill_placeholders(PARAGRAPH[lang], facts) for lang in rf.LANGUAGES}
    return facts, {lang: rt.render_report(facts, lang, filled[lang]) for lang in rf.LANGUAGES}


@pytest.mark.parametrize("lang", ["de", "en"])
def test_every_required_field_value_is_in_the_report(lang):
    facts, reports = make()
    rendered = rf.render_facts(facts, lang)
    for field in rf.REQUIRED_FIELDS:
        assert rendered[field] in reports[lang], field


def lines_of(text):
    return text.split("\n")


def test_type_of_notification_and_title_have_their_own_labelled_lines():
    facts, reports = make()
    assert "Type of notification: Vulnerability" in lines_of(reports["en"])
    assert f"Title: {facts['title']['en']}" in lines_of(reports["en"])
    assert "Art der Meldung: Schwachstelle" in lines_of(reports["de"])
    assert f"Titel: {facts['title']['de']}" in lines_of(reports["de"])


def test_every_field_has_its_own_whole_labelled_line_in_a_fixed_order():
    facts, reports = make()
    for lang in rf.LANGUAGES:
        rendered = rf.render_facts(facts, lang)
        labels = rt.LABELS[lang]
        expected = [f"{labels['notification_type']}: {rendered['notification_type']}", f"{labels['title']}: {rendered['title']}",
                    f"{labels['manufacturer']}: {rendered['manufacturer']}", f"{labels['product_name']}: {rendered['product_name']}",
                    f"{labels['component']}: {rendered['component']} {rendered['version']}", f"{labels['cve_id']}: {rendered['cve_id']}",
                    f"{labels['awareness']}: {rendered['awareness']}", f"{labels['deadline']}: {rendered['deadline']}",
                    f"{labels['member_states']}: {rendered['member_states']}", f"{labels['evidence']}: {rendered['evidence']}"]
        lines = lines_of(reports[lang])
        positions = [lines.index(line) for line in expected]
        assert positions == sorted(positions) and len(set(positions)) == len(positions)


def test_german_and_english_labels_for_the_other_fields():
    _, reports = make()
    for label in ("Manufacturer:", "Product:", "Affected component:", "Vulnerability ID (CVE):", "Awareness time:",
                  "Calculated deadline (awareness time + 24 hours):", "EU Member States where the product is made available:",
                  "Source:", "Assessment:"):
        assert label in reports["en"], label
    for label in ("Hersteller:", "Produkt:", "Betroffene Komponente:", "Schwachstellen-ID (CVE):", "Zeitpunkt des Bewusstwerdens:",
                  "Berechnete Frist (Zeitpunkt des Bewusstwerdens + 24 Stunden):",
                  "EU-Mitgliedstaaten, in denen das Produkt bereitgestellt wird:", "Quelle:", "Einordnung:"):
        assert label in reports["de"], label


def test_the_report_says_it_is_a_draft_and_nothing_was_sent():
    _, reports = make()
    assert "DRAFT" in reports["en"] and "Nothing has been sent" in reports["en"]
    assert "ENTWURF" in reports["de"] and "Es wurde nichts gesendet" in reports["de"]


def test_the_status_sentence_is_careful_about_the_legal_meaning():
    _, reports = make()
    assert "A human decides whether it is reportable under the CRA" in reports["en"]
    assert "Ein Mensch entscheidet, ob sie nach dem CRA meldepflichtig ist" in reports["de"]
    assert "Known Exploited Vulnerabilities (KEV)" in reports["en"]
    assert "did not verify that the vulnerability is exploited in this product" in reports["en"]
    assert "nicht geprüft, ob die Schwachstelle in diesem Produkt ausgenutzt wird" in reports["de"]


@pytest.mark.parametrize("via,en,de", [
    ("alias", "rests on an alias", "beruht auf einem Alias"),
    ("upstream", "rests on an upstream reference", "beruht auf einem Upstream-Verweis"),
])
def test_a_weaker_cve_link_is_said_out_loud(via, en, de):
    _, reports = make(kev_finding(exploited_cve_matched_on=via))
    assert en in reports["en"] and de in reports["de"]


def test_a_direct_id_match_has_no_weaker_link_sentence():
    _, reports = make(kev_finding(exploited_cve_matched_on="id"))
    assert "rests on" not in reports["en"] and "beruht auf" not in reports["de"]


def test_the_status_sentence_names_the_human_evidence_when_that_was_the_reason(tmp_path):
    _, reports = make(evidence_finding(), evidence_dir=evidence_folder(tmp_path))
    assert "human evidence file" in reports["en"] and "menschliche Nachweisdatei" in reports["de"]
    assert "Known Exploited Vulnerabilities (KEV)" not in reports["en"]
    assert "Source: https://example.org/report (20 Oct 2026)" in lines_of(reports["en"])
    assert "Quelle: https://example.org/report (20.10.2026)" in lines_of(reports["de"])
    for text in reports.values():
        assert re.findall(r"https?://\S+", text) == ["https://example.org/report"]


@pytest.mark.parametrize("paragraph", [
    "first line\nDeadline: 31 Dec 2030", "x\r\ny", "x" + chr(0x2028) + "Status: APPROVED", "x" + chr(0x202e) + "evil", "x\x85y", "", "   ", "a" * 1001,
    "has {a} brace", "stray }",
])
def test_a_paragraph_that_is_not_one_printable_line_is_refused(paragraph):
    facts = rf.build_facts(PRODUCT, kev_finding(), kev_ids=KEV_IDS)
    with pytest.raises(rf.FactsError):
        rt.render_report(facts, "en", paragraph)


def test_edited_facts_are_refused_by_every_public_function():
    facts = rf.build_facts(PRODUCT, kev_finding(), kev_ids=KEV_IDS)
    facts["component"] = "log{4}j"
    for call in (lambda: rt.render_report(facts, "en", "x"), lambda: rt.status_sentence(facts, "en"),
                 lambda: rt.fill_placeholders("x", facts)):
        with pytest.raises(rf.FactsError):
            call()
    del facts["title"]
    with pytest.raises(rf.FactsError):
        rt.status_sentence(facts, "de")


def test_fill_placeholders_refuses_a_paragraph_that_is_not_text():
    facts = rf.build_facts(PRODUCT, kev_finding(), kev_ids=KEV_IDS)
    for bad in (None, 5, b"x"):
        with pytest.raises(rf.FactsError):
            rt.fill_placeholders(bad, facts)


def test_the_ai_paragraph_stands_after_the_summary_heading():
    facts, reports = make()
    assert re.search(r"Summary:\nSmartHeat X1 Thermostat uses log4j-core\. See CVE-2021-44228\.\n", reports["en"])
    assert re.search(r"Zusammenfassung:\nSmartHeat X1 Thermostat nutzt log4j-core\. Siehe CVE-2021-44228\.\n", reports["de"])


def test_placeholders_are_filled_and_no_braces_are_left():
    _, reports = make()
    assert "{" not in reports["en"] and "}" not in reports["en"]
    assert "{" not in reports["de"] and "}" not in reports["de"]


def test_a_value_that_looks_like_a_placeholder_is_refused_and_filling_is_one_pass():
    facts = rf.build_facts(PRODUCT, kev_finding(), kev_ids=KEV_IDS)
    facts["product_name"] = "{cve_id}"  # cannot come out of build_facts; a hand-edited facts.json is refused
    with pytest.raises(rf.FactsError):
        rt.fill_placeholders("{product_name} {cve_id}", facts)
    ok = rf.build_facts(PRODUCT, kev_finding(), kev_ids=KEV_IDS)
    assert rt.fill_placeholders("{cve_id}{cve_id}", ok) == "CVE-2021-44228CVE-2021-44228"


def test_only_the_three_known_placeholders_are_filled():
    facts = rf.build_facts(PRODUCT, kev_finding(), kev_ids=KEV_IDS)
    assert rt.fill_placeholders("{version} {unknown} {product_name}", facts) == "{version} {unknown} SmartHeat X1 Thermostat"
    assert rt.PLACEHOLDERS == ("product_name", "component", "cve_id")


def test_the_template_with_a_human_set_awareness_time_shows_berlin_time_and_deadline():
    _, reports = make(awareness=datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc))
    assert "24 Oct 2026, 14:00 (Berlin, CEST)" in reports["en"]
    assert "25 Oct 2026, 13:00 (Berlin, CET)" in reports["en"]
    assert "24.10.2026, 14:00 Uhr (Berlin, MESZ)" in reports["de"]
    assert "NOT SET YET" not in reports["en"]


def test_without_an_awareness_time_the_placeholders_say_so():
    _, reports = make()
    assert "[NOT SET YET - a human must confirm the time]" in reports["en"]
    assert "[NOCH NICHT FESTGELEGT" in reports["de"]


def test_the_template_is_the_same_every_time_apart_from_facts_and_paragraph():
    _, first = make()
    _, second = make()
    assert first == second


def test_the_report_is_plain_text_without_html_or_links_other_than_the_evidence():
    _, reports = make()
    for text in reports.values():
        assert "<" not in text and ">" not in text
        assert re.findall(r"https?://\S+", text) == ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"]


def test_the_renderer_refuses_wrong_input():
    facts = rf.build_facts(PRODUCT, kev_finding(), kev_ids=KEV_IDS)
    with pytest.raises(rf.FactsError):
        rt.render_report(facts, "fr", "x")
    with pytest.raises(rf.FactsError):
        rt.render_report(facts, "en", None)
