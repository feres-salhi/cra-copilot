"""OPTIONAL live test: talks to the REAL Google Gemini API with YOUR key. Fares runs it himself.

It is skipped unless you switch it on on purpose:
    PowerShell:  $env:CRA_LIVE_AI = "1"; .venv\Scripts\python -m pytest tests/test_live_ai.py -v -s
The key is read from the .env file in the project folder (GEMINI_API_KEY, optional GEMINI_MODEL) or from the
environment. The test sends ONE fixed prompt without any product data and prints only the checked paragraphs.
It prints no key. It sends nothing to any authority (the tool has no send function).
"""

import os

import pytest

from src import fact_checker as fc
from src import report_writer as rw
from tests.test_report_facts import KEV_IDS, PRODUCT, kev_finding
from src import report_facts as rf

pytestmark = pytest.mark.skipif(os.environ.get("CRA_LIVE_AI") != "1", reason="live AI test: set CRA_LIVE_AI=1 to run")


def test_the_real_gemini_answer_for_both_languages_is_a_valid_one_line_text_or_the_fallback_is_used(capsys):
    ai = rw.make_gemini_ai()  # reads GEMINI_API_KEY / GEMINI_MODEL from .env or the environment
    facts = rf.build_facts(PRODUCT, kev_finding(), kev_ids=KEV_IDS)
    draft = rw.build_draft(facts, ai)
    with capsys.disabled():
        print()
        print("source of the summary:", draft.source)
        print("fact check:", draft.check.status, draft.check.problems)
        for lang in rf.LANGUAGES:
            print(f"--- {lang} ---")
            print(draft.paragraphs[lang])
    assert draft.check.status == "PASS"  # either the AI text passed the checker, or the fixed fallback text was used
    assert draft.source["mode"] in ("ai", "fallback")


def test_the_real_gemini_answer_alone_passes_the_fact_checker_otherwise_tell_me_why(capsys):
    """If this fails, the AI wording is rejected by the rules (not a bug): read the problems and adjust the prompt."""
    ai = rw.make_gemini_ai()
    paragraphs = {lang: ai(rw.build_prompt(lang, "kev")).strip() for lang in rf.LANGUAGES}
    result = fc.check_paragraphs(paragraphs)
    with capsys.disabled():
        print()
        print(paragraphs)
        print("pass 1:", result.status, result.problems)
    assert result.ok, result.problems
