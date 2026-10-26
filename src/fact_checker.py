"""Part 4: the fact checker. Plain code (no AI) that rejects any draft with facts that are not in facts.json.

Pass 1 looks at the AI paragraph alone, BEFORE the placeholders are filled. No code can judge the meaning of free text,
so the paragraph may only be made of the APPROVED SENTENCES in `summary_sentences` (exact match; one to five different
ones, in the allowed order, the first one says what the product contains, the same ones in German and English, only
those that apply to the reason of the case). Nothing the AI wrote outside those sentences ever reaches a report.
Pass 2 looks at the finished report AFTER the placeholders were filled:
    - length, normal form (NFKC) and a strict character set (blocks look-alike letters and control characters),
    - the report must be EXACTLY what the template writes from facts.json (so every required field, ID, version, date,
      time and link is exactly the one in the facts, and nothing else was added or changed),
    - and the summary line must be made of approved sentences with the facts filled in.

Any problem means REJECTED. The checker never "repairs" a draft and never decides whether a product is affected.
It never raises on odd input: a crash is reported as FAIL.
"""

import re
import unicodedata
from dataclasses import dataclass, field

from src import report_template as rt
from src import summary_sentences as ss
from src.report_facts import FactsError, LANGUAGES, validate_facts

MAX_REPORT_LENGTH = 20_000
_REPORT_CHARS = re.compile(r"[\x20-\x7eäöüÄÖÜß\n]*")


@dataclass
class CheckResult:
    problems: list = field(default_factory=list)
    texts: dict = field(default_factory=dict)  # pass 1: the paragraph (with placeholders) built from the approved table
    ids: list = field(default_factory=list)  # pass 1: the chosen sentence ids
    reports: dict | None = None  # check_draft: the finished reports

    @property
    def ok(self):
        return not self.problems

    @property
    def status(self):
        return "PASS" if self.ok else "FAIL"

    def as_dict(self):
        return {"status": self.status, "problems": list(self.problems)}


# ---------------------------------------------------------------- pass 1


def check_paragraphs(paragraphs, exploited_via):
    """Pass 1 for both languages. `paragraphs` is {"de": text, "en": text}; `exploited_via` is "kev" or "evidence_file"."""
    result = CheckResult()
    try:
        if not isinstance(paragraphs, dict) or set(paragraphs) != set(LANGUAGES):
            result.problems.append("pass 1 needs exactly one paragraph per language (de and en)")
            return result
        chosen = {}
        for lang in LANGUAGES:
            text = paragraphs[lang]
            if isinstance(text, str) and len(text) > rt.MAX_PARAGRAPH_LENGTH:  # before anything else runs on it
                result.problems.append(f"{lang}: the paragraph is longer than {rt.MAX_PARAGRAPH_LENGTH} characters")
                continue
            if isinstance(text, str):
                text = unicodedata.normalize("NFKC", text)  # a full-width letter becomes a plain one; look-alikes stay and fail
            ids, problems = ss.parse(text, lang, exploited_via)
            result.problems += problems
            chosen[lang] = ids
        if not result.problems and chosen["de"] != chosen["en"]:
            result.problems.append("the German and the English paragraph must use the same sentences in the same order")
        if result.ok:
            result.ids = chosen["en"]
            result.texts = {lang: ss.compose(result.ids, lang) for lang in LANGUAGES}
    except Exception as error:  # a crash must never look like a pass
        result.problems.append(f"pass 1 failed unexpectedly ({type(error).__name__})")
    return result


# ---------------------------------------------------------------- pass 2


def _check_report(facts, lang, text, summary_source):
    if not isinstance(text, str) or not text.strip():
        return [f"{lang}: the report is missing or empty"]
    if len(text) > MAX_REPORT_LENGTH:
        return [f"{lang}: the report is longer than {MAX_REPORT_LENGTH} characters"]
    problems = []
    if unicodedata.normalize("NFKC", text) != text:
        problems.append(f"{lang}: the report has characters that change when normalised (look-alike or ligature letters)")
    if not _REPORT_CHARS.fullmatch(text):
        bad = next(ch for ch in text if not _REPORT_CHARS.fullmatch(ch))
        problems.append(f"{lang}: the report contains the character {ascii(bad)}, which is not allowed")

    labels = rt.LABELS[lang]
    lines = text.split("\n")
    source_lines = {labels["source_ai"]: "ai", labels["source_code"]: "code"}
    found = [source_lines[line] for line in lines if line in source_lines]
    if len(found) != 1 or (summary_source is not None and found[0] != summary_source):
        problems.append(f"{lang}: the summary source line is missing, doubled or not the expected one")
    heading = f"{labels['summary']}:"
    if lines.count(heading) != 1 or lines.index(heading) + 1 >= len(lines) or len(found) != 1:
        problems.append(f"{lang}: the report does not have the fixed summary structure")
        return problems
    paragraph = lines[lines.index(heading) + 1]

    # The summary line must be approved sentences with the facts filled in ...
    ids, paragraph_problems = ss.parse(paragraph, lang, facts["exploited_via"], lambda s: rt.fill_placeholders(s, facts))
    problems += [f"{lang}: summary line: {p}" for p in paragraph_problems]
    # ... and the whole report must be exactly what the template writes from the facts.
    try:
        rebuilt = rt.render_report(facts, lang, paragraph, found[0])
    except FactsError as error:
        problems.append(f"{lang}: the report could not be rebuilt ({ascii(str(error))[:80]})")
    else:
        if rebuilt != text:
            first = next((i for i, (a, b) in enumerate(zip(rebuilt.split("\n"), lines), 1) if a != b), "end")
            problems.append(f"{lang}: the report is not exactly what the template writes from the facts (first difference: line {first})")
    return problems


def check_reports(facts, reports, summary_source=None):
    """Pass 2 on the finished reports {"de": text, "en": text}. `summary_source` ("ai" or "code") is optional."""
    result = CheckResult()
    try:
        validate_facts(facts)
        if not isinstance(reports, dict) or set(reports) != set(LANGUAGES):
            result.problems.append("pass 2 needs exactly one finished report per language (de and en)")
            return result
        for lang in LANGUAGES:
            result.problems += _check_report(facts, lang, reports[lang], summary_source)
    except FactsError as error:
        result.problems.append(f"the facts are not valid: {error}")
    except Exception as error:  # a crash must never look like a pass
        result.problems.append(f"pass 2 failed unexpectedly ({type(error).__name__})")
    return result


# ---------------------------------------------------------------- both passes


def check_draft(facts, paragraphs, summary_source="code"):
    """Pass 1, then fill the placeholders and write the reports, then pass 2. Returns a CheckResult.

    `summary_source` ("ai" or "code") is written into the report. `reports` holds the finished texts only when
    everything passed.
    """
    try:
        validate_facts(facts)
        first = check_paragraphs(paragraphs, facts["exploited_via"])
        if not first.ok:
            return first
        reports = {lang: rt.render_report(facts, lang, rt.fill_placeholders(first.texts[lang], facts), summary_source)
                   for lang in LANGUAGES}
        second = check_reports(facts, reports, summary_source)
        return CheckResult(second.problems, first.texts, first.ids, reports if second.ok else None)
    except FactsError as error:
        return CheckResult([f"the draft could not be written: {error}"])
    except Exception as error:  # a crash must never look like a pass
        return CheckResult([f"the check failed unexpectedly ({type(error).__name__})"])
