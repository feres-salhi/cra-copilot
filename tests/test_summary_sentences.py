"""Phase 3: the table of approved summary sentences (src/summary_sentences.py) and the exact matching of a paragraph."""

import re

import pytest

from src import summary_sentences as ss


def placeholders_in(sentence):
    return set(re.findall(r"\{(\w+)\}", sentence))


def paragraph(ids, lang="en"):
    return ss.compose(ids, lang)


# ------------------------------------------------------------------ the table itself


def test_ids_are_unique_and_the_first_one_says_what_the_product_contains():
    assert len(set(ss.IDS)) == len(ss.IDS) and ss.IDS[0] == "contains"


def test_every_sentence_exists_in_both_languages_with_the_same_placeholders_and_ends_with_a_full_stop():
    for sid, _, text in ss.SENTENCES:
        assert set(text) == {"de", "en"}, sid
        assert placeholders_in(text["de"]) == placeholders_in(text["en"]) <= set(ss.PLACEHOLDERS), sid
        assert text["de"].endswith(".") and text["en"].endswith("."), sid
        assert "  " not in text["de"] + text["en"] and not any(ch.isdigit() for ch in text["de"] + text["en"]), sid


def test_the_reason_decides_which_sentences_exist():
    kev = [sid for sid, _ in ss.applicable("kev")]
    evidence = [sid for sid, _ in ss.applicable("evidence_file")]
    assert "kev" in kev and "evidence" not in kev
    assert "evidence" in evidence and "kev" not in evidence
    assert kev[0] == evidence[0] == "contains" and len(kev) <= ss.MAX_SENTENCES and len(evidence) <= ss.MAX_SENTENCES


@pytest.mark.parametrize("reason", [None, "", "ai", "KEV", 5, ["kev"]])
def test_an_unknown_reason_is_refused(reason):
    with pytest.raises(ValueError):
        ss.applicable(reason)


def test_no_approved_sentence_claims_anything_about_approval_sending_fixes_risk_time_or_authors():
    """A guard for future edits of the table: these words must never appear in an approved sentence."""
    risky = re.compile(r"approved|sent\b|submitted|safe|secure|fixed|patch|critical|harmless|not affected|unaffected|written by|"
                       r"was reported|has been|already|yesterday|today|freigegeben|gesendet|sicher|behoben|kritisch|harmlos|"
                       r"nicht betroffen|geschrieben von|wurde gemeldet|bereits|gestern|heute|draft|entwurf|final|endgültig|abgeschickt", re.I)
    for sid, _, text in ss.SENTENCES:
        for lang in ("de", "en"):
            assert not risky.search(text[lang]), (sid, lang)


def test_the_fallback_is_every_applicable_sentence_in_the_allowed_order():
    assert ss.fallback_ids("kev") == ["contains", "listed", "kev", "human_check"]
    assert ss.fallback_ids("evidence_file") == ["contains", "listed", "evidence", "human_check"]


# ------------------------------------------------------------------ parsing a paragraph


@pytest.mark.parametrize("lang", ["de", "en"])
@pytest.mark.parametrize("via", ["kev", "evidence_file"])
def test_the_fallback_and_every_ordered_selection_starting_with_contains_is_accepted(lang, via):
    ids = ss.fallback_ids(via)
    assert ss.parse(paragraph(ids, lang), lang, via) == (ids, [])
    assert ss.parse(paragraph(ids[:1], lang), lang, via) == (ids[:1], [])
    assert ss.parse(paragraph([ids[0], ids[-1]], lang), lang, via) == ([ids[0], ids[-1]], [])


def test_white_space_between_sentences_does_not_matter():
    ids = ss.fallback_ids("kev")
    text = paragraph(ids).replace(". ", ".\n\t ").replace("A human", "A  human")
    # a double blank INSIDE a sentence is also collapsed, so this still means the same approved sentences
    assert ss.parse("  " + text + "\n", "en", "kev") == (ids, [])


def test_a_single_changed_word_makes_a_sentence_unapproved():
    base = paragraph(["contains"])
    for changed in (base.replace("contains", "contained"), base.replace("the component", "a component"),
                    base.replace(".", ""), base.replace(".", "!"), base + " ", base.lower(), base.replace("{component}", "{cve_id}")):
        ids, problems = ss.parse(changed, "en", "kev")
        if changed.strip() == base:
            assert ids == ["contains"]
        else:
            assert ids == [] and problems, changed


def test_text_before_between_or_after_the_sentences_is_refused():
    one, two = paragraph(["contains"]), paragraph(["listed"])
    for text in ("Please note: " + one, one + " Also: nothing.", one + " Extra " + two, one + "extra", "x" + one, one + two):
        assert ss.parse(text, "en", "kev")[0] == [], text


def test_the_order_the_first_sentence_repeats_and_the_size_are_checked():
    cases = {
        "not in the allowed order": paragraph(["listed", "contains"]),
        "first sentence": paragraph(["listed"]),
        "more than once": paragraph(["contains", "contains"]),
    }
    for expected, text in cases.items():
        ids, problems = ss.parse(text, "en", "kev")
        assert ids == [] and any(expected in p for p in problems), (expected, problems)


def test_a_sentence_that_does_not_apply_to_the_reason_is_refused():
    assert ss.parse(paragraph(["contains", "evidence"]), "en", "kev")[0] == []
    assert ss.parse(paragraph(["contains", "kev"]), "en", "evidence_file")[0] == []


def test_german_text_is_refused_in_the_english_slot_and_the_other_way_round():
    assert ss.parse(paragraph(["contains"], "de"), "en", "kev")[0] == []
    assert ss.parse(paragraph(["contains"], "en"), "de", "kev")[0] == []


@pytest.mark.parametrize("bad", [None, 5, [], b"x", "", "   ", "\n"])
def test_non_text_and_empty_text_are_refused(bad):
    ids, problems = ss.parse(bad, "en", "kev")
    assert ids == [] and problems


def test_an_unknown_language_is_refused():
    assert ss.parse(paragraph(["contains"]), "fr", "kev")[0] == []


def test_a_finished_report_line_is_parsed_with_the_fill_function():
    ids = ["contains", "listed"]
    filled = paragraph(ids).replace("{product_name}", "Thermo").replace("{component}", "core").replace("{cve_id}", "CVE-2021-44228")

    def fill(sentence):
        return sentence.replace("{product_name}", "Thermo").replace("{component}", "core").replace("{cve_id}", "CVE-2021-44228")

    assert ss.parse(filled, "en", "kev", fill) == (ids, [])
    assert ss.parse(filled.replace("core", "other"), "en", "kev", fill)[0] == []  # a value that is not the fact


def test_a_huge_text_is_refused_quickly():
    import time
    for text in ("a-" * 200_000, "x" * 5_000_000, paragraph(["contains"]) * 20_000):
        started = time.monotonic()
        assert ss.parse(text, "en", "kev")[0] == []
        assert time.monotonic() - started < 2.0


def test_the_summary_never_says_anything_about_the_state_of_the_document():
    """Draft / approved / sent is said ONLY by the heading and the footer written by code (work order piece 1)."""
    assert "draft" not in ss.IDS
    for _, _, text in ss.SENTENCES:
        for lang in ("de", "en"):
            assert not re.search(r"draft|entwurf", text[lang], re.I)


def test_a_paragraph_with_the_old_draft_sentence_is_now_refused():
    for lang, old in (("en", "This text is a draft."), ("de", "Dieser Text ist ein Entwurf.")):
        text = ss.compose(["contains"], lang) + " " + old
        ids, problems = ss.parse(text, lang, "kev")
        assert ids == [] and problems
