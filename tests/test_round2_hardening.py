"""Phase 3, pieces 4 and 5, second review round: every finding of the code reviewer and the security auditor."""

import json

import pytest

from src import env_loader as el
from src import fact_checker as fc
from src import news_watcher as nw
from src import report_facts as rf
from src import report_writer as rw
from tests.test_fact_checker import GOOD, facts_for, reports_for, with_text
from tests.test_report_facts import KEV_IDS, PRODUCT, kev_finding
from tests.test_report_writer_ai import GOOD_AI, FakeAI, FakeNetwork, SECRET, gemini_answer, patch_opener, _Recorder, GEMINI_URL

# Sentences made only of ordinary words that used to be on the list, but that claim something (security auditor, round 2)
MEANING_CLAIMS_EN = [
    "The early warning notification was reported to the authority and a person did review it.",
    "The vulnerability {cve_id} is described in another component. {product_name} may use other software.",
    "{product_name} is responsible for the flaw. The product must be reported.",
    "The component {component} was exploited before {product_name} used it.",
    "A person did review it and approved it.",
]
MEANING_CLAIMS_DE = [
    "Die Frühwarnung wurde gemeldet. Die Behörde hat die Meldung.",
    "Die Schwachstelle {cve_id} ist in einer anderen Komponente beschrieben.",
    "{product_name} ist für die Schwachstelle verantwortlich.",
]


@pytest.mark.parametrize("text", MEANING_CLAIMS_EN)
def test_sentences_that_claim_something_are_refused_in_english(text):
    assert not fc.check_paragraphs(with_text("en", text)).ok, text


@pytest.mark.parametrize("text", MEANING_CLAIMS_DE)
def test_sentences_that_claim_something_are_refused_in_german(text):
    assert not fc.check_paragraphs(with_text("de", text)).ok, text


def test_the_approved_word_lists_are_small_and_hold_no_word_about_impact_time_authority_or_blame():
    risky_en = {"authority", "authorities", "notification", "responsible", "another", "other", "was", "were", "been", "had",
                "did", "should", "review", "decide", "person", "warning", "early", "information", "problem", "flaw", "not", "no"}
    risky_de = {"behörde", "behörden", "meldung", "verantwortlich", "andere", "war", "waren", "hat", "haben", "frühwarnung",
                "nicht", "kein", "keine", "problem", "probleme"}
    assert not risky_en & fc.VOCABULARY["en"] and not risky_de & fc.VOCABULARY["de"]
    assert len(fc.VOCABULARY["en"]) < 80 and len(fc.VOCABULARY["de"]) < 80


@pytest.mark.parametrize("text", ["Product X contains X.", "X", "x contains {component}."])
def test_the_stand_in_letter_for_a_placeholder_cannot_be_typed_by_the_ai(text):
    assert not fc.check_paragraphs(with_text("en", text)).ok


@pytest.mark.parametrize("text", ["{component}-a is listed.", "in{component} is listed.", "{component}s is listed.",
                                  "a-{component} is listed.", "{cve_id}-a"])
def test_a_placeholder_glued_to_a_letter_or_hyphen_is_refused(text):
    result = fc.check_paragraphs(with_text("en", text))
    assert not result.ok and any("separated" in p for p in result.problems or [""]), result.problems


def test_a_placeholder_next_to_punctuation_or_a_space_is_fine():
    assert fc.check_paragraphs(with_text("en", "({component}), {cve_id}; {product_name}.")).ok


@pytest.mark.parametrize("quote", [0x201e, 0x201c, 0x201d, 0x2018, 0x2019, 0x2013])
def test_typographic_quotes_and_dashes_are_refused_so_pass_1_and_pass_2_allow_the_same_characters(quote):
    text = "{component} " + chr(quote) + "is listed" + chr(quote) + "."
    assert not fc.check_paragraphs(with_text("en", text)).ok


def test_a_short_component_name_inside_an_ordinary_word_does_not_confuse_pass_2():
    finding = kev_finding(component="lib")
    facts = rf.build_facts(PRODUCT, finding, kev_ids=KEV_IDS)
    paragraphs = {"en": "{product_name} contains {component} library software.", "de": "{product_name} enthält {component} Bibliothek Software."}
    result = fc.check_draft(facts, paragraphs)
    assert result.ok, result.problems
    assert fc.check_reports(facts, result.reports).ok


def test_a_fact_value_that_equals_a_placeholder_word_is_not_unfilled_inside_other_text():
    finding = kev_finding(component="name")
    facts = rf.build_facts({**PRODUCT, "product_name": "Name"}, finding, kev_ids=KEV_IDS)
    result = fc.check_draft(facts, GOOD)
    assert result.ok, result.problems


# ------------------------------------------------------------------ the writer


def test_a_line_break_between_sentences_in_the_ai_answer_does_not_cause_a_fallback():
    answers = {lang: text.replace(". ", ".\n") for lang, text in GOOD_AI.items()}
    assert "\n" in answers["en"]
    draft = rw.build_draft(rw_facts(), FakeAI(answers=answers))
    assert draft.source["mode"] == "ai" and draft.check.status == "PASS"
    assert "\n\n" not in draft.reports["en"].split("Summary:")[1].split("Summary text:")[0].strip("\n") + "x"


def rw_facts():
    return rf.build_facts(PRODUCT, kev_finding(), kev_ids=KEV_IDS)


def test_tabs_and_double_spaces_in_the_ai_answer_are_collapsed():
    answers = {lang: "  " + text.replace(" ", " \t ") + "  " for lang, text in GOOD_AI.items()}
    assert rw.build_draft(rw_facts(), FakeAI(answers=answers)).source["mode"] == "ai"


def test_the_prompt_asks_for_each_placeholder_exactly_once():
    for lang in rf.LANGUAGES:
        assert "exactly once" in rw.build_prompt(lang, "kev")


def test_the_prompt_lists_the_approved_words_of_its_language():
    en, de = rw.build_prompt("en", "kev"), rw.build_prompt("de", "kev")
    for word in ("exploited", "sources", "human"):
        assert word in en
    for word in ("ausgenutzt", "quellen", "mensch"):
        assert word in de
    assert "authority" not in en and "responsible" not in en


def test_a_bad_fact_is_not_reported_as_an_ai_failure():
    facts = rw_facts()
    facts["exploited_via"] = "ai"
    with pytest.raises(rf.FactsError):
        rw.build_draft(facts, FakeAI())


def request_body_for(model):
    net = FakeNetwork(gemini_answer("ok."))
    rw.gemini_generate("p", SECRET, model, net)
    return json.loads(net.calls[0]["body"])


def test_flash_models_get_the_thinking_budget_off_and_a_roomy_output_limit():
    config = request_body_for("gemini-2.5-flash")["generationConfig"]
    assert config["thinkingConfig"] == {"thinkingBudget": 0} and config["maxOutputTokens"] == 2048
    assert request_body_for("gemini-2.5-flash-lite")["generationConfig"]["thinkingConfig"] == {"thinkingBudget": 0}


def test_other_models_do_not_get_a_thinking_setting_they_may_refuse():
    assert "thinkingConfig" not in request_body_for("gemini-2.5-pro")["generationConfig"]


@pytest.mark.parametrize("key", ["AQ.Ab8" + "x" * 30, "a.b-c_d" * 4])
def test_a_key_with_a_dot_is_accepted(key):
    assert el.valid_api_key(key)


def test_a_key_with_a_space_or_a_line_break_is_still_refused():
    for key in ("a b" * 10, "a\nb" * 10, "a/b" * 10):
        assert not el.valid_api_key(key)


# ------------------------------------------------------------------ http_fetch header checks


@pytest.mark.parametrize("headers", [{"x-goog-api-key": "café-key"}, {"x-goog-api-key": "€-key"},
                                    {"Host": "evil.example"}, {"host": "evil.example"}, {"Content-Length": "5"},
                                    {"Transfer-Encoding": "chunked"}, {"Connection": "close"}, {"Content-Type": "text/plain"},
                                    {"User-Agent": "x"}])
def test_non_ascii_values_and_request_framing_headers_are_refused(monkeypatch, headers):
    patch_opener(monkeypatch, _Recorder())
    with pytest.raises(nw.FetchError):
        nw.http_fetch(GEMINI_URL, b"{}", 1000, headers=headers, allowed_hosts={"generativelanguage.googleapis.com"})


def test_a_refused_header_never_appears_in_the_error_message(monkeypatch):
    patch_opener(monkeypatch, _Recorder())
    leak = "SECRETHEADERVALUE-" + "x" * 30
    for headers in ({"x-goog-api-key": leak + "\n"}, {"x-goog-api-key": leak + "é"}, {"Host": leak}, {"bad name": leak}):
        with pytest.raises(nw.FetchError) as caught:
            nw.http_fetch(GEMINI_URL, b"{}", 1000, headers=headers, allowed_hosts={"generativelanguage.googleapis.com"})
        assert leak not in str(caught.value) and leak not in repr(caught.value)
