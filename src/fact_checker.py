"""Part 4: the fact checker. Plain code (no AI) that rejects any draft with facts that are not in facts.json.

Pass 1 looks at the AI paragraph alone, BEFORE the placeholders are filled:
    - the text is normalised (NFKC), then only plain characters are allowed (blocks look-alike letters),
    - no digits at all, only the three allowed placeholders (the same set in German and English), no stray braces,
    - every word must be on a SMALL APPROVED WORD LIST for that language (a deny-list alone cannot stop a
      false claim written in words nobody thought of, so the AI may only use plain, neutral words),
    - and no forbidden word (German + English, no exceptions in version 1).
Pass 2 looks at the finished report AFTER the placeholders were filled:
    - the report must be EXACTLY what the template writes from facts.json (so no extra line, no changed value),
    - every required field is there once in both languages, every ID, version, date, time and link is in the facts,
    - no brace is left, no odd character, and the summary paragraph passes the pass 1 rules again.

Any problem means REJECTED. The checker never "repairs" a draft and never decides whether a product is affected.
It never raises on odd input: a crash is reported as FAIL.
"""

import re
import unicodedata
from dataclasses import dataclass, field

from src import report_template as rt
from src.report_facts import FactsError, LANGUAGES, render_facts, validate_facts

MAX_PARAGRAPH_LENGTH = rt.MAX_PARAGRAPH_LENGTH
MAX_REPORT_LENGTH = 20_000

# ---------------------------------------------------------------- pass 1

_ALLOWED_CHARS = re.compile(r"[A-Za-z äöüÄÖÜß.,;!?'\"()\-]*")
_BRACE_GROUP = re.compile(r"\{[^{}]*\}")
_WORD = re.compile(r"[A-Za-zÄÖÜäöüß]+")

# The only words an AI paragraph may use. Plain, neutral words: what the product contains, that a public list names the
# vulnerability as exploited, and that a human must check everything. Nothing about impact, fixes, risk or time.
VOCABULARY = {
    "en": frozenset("""
        a an the and or that this these which it its in of on to with from for as by
        be is are may might can must
        product component components software library
        contain contains
        list lists listed public sources source vulnerability vulnerabilities
        exploited possible possibly
        draft written code standard wording
        human check each statement before anything reported
    """.split()),
    "de": frozenset("""
        ein eine einer einem einen eines der die das den dem des und oder dass daß
        ist sind wird werden wurde kann können muss in im von mit für aus als zu bevor jede
        dieser diese dieses sie es
        enthält enthalten komponente komponenten produkt software bibliothek
        gelistet geführt schwachstelle schwachstellen sicherheitslücke öffentlichen öffentliche quellen quelle ausgenutzt
        entwurf textbausteinen festen feste erstellt mensch prüfen aussage gemeldet etwas möglich möglicherweise
    """.split()),
}

_EN_NUMBERS = (
    "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen "
    "eighteen nineteen twenty thirty forty fifty sixty seventy eighty ninety dozen"
).split()
_DE_NUMBERS = (
    "null eins zwei drei vier fünf sechs sieben acht neun zehn elf zwölf dreizehn vierzehn fünfzehn sechzehn siebzehn "
    "achtzehn neunzehn zwanzig dreißig dreissig vierzig fünfzig sechzig siebzig achtzig neunzig dutzend"
).split()

# (name, regex) - matched against the lower-cased text. German and English lists are applied to both paragraphs.
# Stems are matched anywhere in a word on purpose (bugfix, Sicherheitspatch): a false alarm only means "use the fallback".
_GAP = r"(?:\W+\w+){0,4}?\W+"  # up to four words between "not" and "affected" ("nicht von X betroffen")
_FORBIDDEN = [
    ("not affected", r"\bnot\b" + _GAP + r"affected"), ("unaffected", r"unaffected"),
    ("nicht betroffen", r"\bnicht\b" + _GAP + r"betroffen"), ("unbetroffen", r"unbetroffen"),
    ("fix", r"fix"), ("patch", r"patch"), ("behoben / Behebung", r"beheb|behob"), ("resolved / gelöst", r"resolved|gelöst"),
    ("mitigated", r"mitigat|mitigiert"), ("critical / kritisch", r"critical|kritisch"), ("CVSS", r"cvss"),
    ("percent", r"%|percent|prozent"), ("safe", r"safe|safety"), ("sicher", r"sicher(?!heitslücke)"), ("secure", r"secur"),
    ("all versions", r"\ball\b" + _GAP + r"versions?\b"), ("alle Versionen", r"\balle\b" + _GAP + r"versionen\b"),
    ("harmless / harmlos", r"harmless|harmlos"), ("no risk / kein Risiko", r"\bno\s+risk|\bkein\s+risiko"),
    ("approved / sent", r"\b(?:approved|sent|submitted|freigegeben|gesendet|eingereicht)\b"),
    ("link-like text", r"\b(?:https?|www)\b|\b\w+\.[a-z]{2,}\b"),
    ("number word", r"\b(?:" + "|".join(_EN_NUMBERS + _DE_NUMBERS) + r")\b|hundred|thousand|million|billion|hundert|tausend|milliarde"),
    ("month name", r"\b(?:january|february|march|april|june|july|august|september|october|november|december|"
                   r"januar|februar|märz|juni|juli|oktober|dezember|jänner)\b"),
]
_FORBIDDEN_COMPILED = [(name, re.compile(pattern)) for name, pattern in _FORBIDDEN]


@dataclass
class CheckResult:
    problems: list = field(default_factory=list)
    texts: dict = field(default_factory=dict)  # pass 1: the normalised paragraphs
    reports: dict | None = None  # check_draft: the finished reports

    @property
    def ok(self):
        return not self.problems

    @property
    def status(self):
        return "PASS" if self.ok else "FAIL"

    def as_dict(self):
        return {"status": self.status, "problems": list(self.problems)}


def _shown(text, limit=40):
    """Make any text safe to put into a problem message."""
    return ascii(text)[:limit]


def _check_paragraph(text, lang):
    """Returns (normalised_text, placeholders_used, problems) for one AI paragraph."""
    if not isinstance(text, str):
        return None, set(), [f"{lang}: the paragraph is not text"]
    if len(text) > MAX_PARAGRAPH_LENGTH * 2:  # before any pattern runs: a huge text must not cost time
        return None, set(), [f"{lang}: the paragraph is longer than {MAX_PARAGRAPH_LENGTH} characters"]
    normalised = unicodedata.normalize("NFKC", text)
    if not normalised.strip():
        return normalised, set(), [f"{lang}: the paragraph is empty"]
    if len(normalised) > MAX_PARAGRAPH_LENGTH:
        return normalised, set(), [f"{lang}: the paragraph is longer than {MAX_PARAGRAPH_LENGTH} characters"]

    problems = []
    used = set()
    for match in _BRACE_GROUP.finditer(normalised):
        name = match.group(0)[1:-1]
        if name in rt.PLACEHOLDERS:
            used.add(name)
        else:
            problems.append(f"{lang}: the placeholder {_shown(match.group(0))} is not allowed")
    for match in _BRACE_GROUP.finditer(normalised):
        before = normalised[match.start() - 1] if match.start() else " "
        after = normalised[match.end()] if match.end() < len(normalised) else " "
        if (before.isalpha() or before == "-" or after.isalpha() or after == "-") and match.group(0)[1:-1] in rt.PLACEHOLDERS:
            problems.append(f"{lang}: a placeholder must be separated from letters and hyphens by a space or punctuation")
            break
    cleaned = _BRACE_GROUP.sub(lambda m: " X " if m.group(0)[1:-1] in rt.PLACEHOLDERS else " ", normalised)
    words_text = _BRACE_GROUP.sub(" ", normalised)
    if "{" in cleaned or "}" in cleaned:
        problems.append(f"{lang}: a stray brace is left (broken or nested placeholder)")
        cleaned = cleaned.replace("{", " ").replace("}", " ")

    if any(ch.isdigit() for ch in cleaned):
        problems.append(f"{lang}: the paragraph contains a digit (digits are not allowed)")
    if not _ALLOWED_CHARS.fullmatch(cleaned):
        bad = next(ch for ch in cleaned if not _ALLOWED_CHARS.fullmatch(ch))
        problems.append(f"{lang}: the character {_shown(bad)} is not allowed (plain letters and a few punctuation marks only)")

    lowered = cleaned.lower()
    for name, pattern in _FORBIDDEN_COMPILED:
        if pattern.search(lowered):
            problems.append(f"{lang}: forbidden word or phrase ({name})")
    unknown = sorted({w for w in _WORD.findall(words_text.lower()) if w not in VOCABULARY[lang]})
    if unknown:
        problems.append(f"{lang}: word(s) not on the approved list: {_shown(', '.join(unknown[:8]), 80)}")
    return normalised, used, problems


def check_paragraphs(paragraphs):
    """Pass 1 for both languages. `paragraphs` is {"de": text, "en": text}."""
    result = CheckResult()
    try:
        if not isinstance(paragraphs, dict) or set(paragraphs) != set(LANGUAGES):
            result.problems.append("pass 1 needs exactly one paragraph per language (de and en)")
            return result
        sets = {}
        for lang in LANGUAGES:
            normalised, used, problems = _check_paragraph(paragraphs[lang], lang)
            result.problems += problems
            result.texts[lang] = normalised
            sets[lang] = used
        if sets["de"] != sets["en"]:
            result.problems.append("the German and the English paragraph must use the same placeholders")
    except Exception as error:  # a crash must never look like a pass
        result.problems.append(f"pass 1 failed unexpectedly ({type(error).__name__})")
    return result


# ---------------------------------------------------------------- pass 2

_MONTHS_FULL = ("January|February|March|April|May|June|July|August|September|October|November|December|"
                "Januar|Februar|März|Juni|Juli|Oktober|Dezember|Jänner")
_MONTHS_SHORT = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec"
_TOKENS = (  # order matters: a found token is cut out of the text so a later pattern cannot match a piece of it
    ("link", re.compile(r"(?:https?://|www\.)[^\s<>\"']+|\b[a-z0-9-]+\.(?:com|org|net|de|eu|io|gov|info|ly|xyz|ru|cn)\b[^\s<>\"']*", re.I)),
    ("id", re.compile(
        r"\b(?:CVE|GHSA|PYSEC|OSV|CWE|CAPEC|RHSA|RHBA|ALAS\d*|DSA|DLA|USN|GO|RUSTSEC|MAL|SNYK|JVN|VU|BIT|CGA|GSD|EUVD)-[A-Za-z0-9](?:[A-Za-z0-9:._-]*[A-Za-z0-9])?"
        r"|\b[A-Za-z][A-Za-z0-9]{1,9}-\d[A-Za-z0-9:._-]*[A-Za-z0-9]|\b[A-Za-z][A-Za-z0-9]{1,9}-\d\b", re.I)),
    ("date", re.compile(
        r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?)?"
        r"|\b\d{1,2}[./]\d{1,2}[./]\d{2,4}\b|\b\d{4}/\d{2}/\d{2}\b"
        r"|\b\d{1,2}(?:st|nd|rd|th)?\.? (?:of )?(?:" + _MONTHS_FULL + "|" + _MONTHS_SHORT + r")\.? \d{2,4}\b"
        r"|\b(?:" + _MONTHS_FULL + "|" + _MONTHS_SHORT + r")\.? \d{1,2}(?:st|nd|rd|th)?,? \d{2,4}\b", re.I)),
    ("time", re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b|\b\d{1,2} ?(?:am|pm)\b", re.I)),
    ("version", re.compile(r"\bv\d+(?:\.\d+)*\b|\b\d+(?:\.(?:\d+|x))+\b", re.I)),
)
_REPORT_CHARS = re.compile(r"[\x20-\x7eäöüÄÖÜß\n]*")


def extract_tokens(text):
    """{"link": {...}, "id": {...}, "date": {...}, "time": {...}, "version": {...}} found in a text (lower-cased)."""
    found = {kind: set() for kind, _ in _TOKENS}
    for kind, pattern in _TOKENS:
        def take(match, kind=kind):
            token = match.group(0)
            if kind == "link":
                token = token.rstrip(".,;:!?)")
            found[kind].add(token.lower())
            return " "
        text = pattern.sub(take, text)
    return found


def _unfill(paragraph, facts):
    """Put the placeholders back so the paragraph can be judged by the pass 1 rules.

    One pass, longest value first, only where the value stands alone (not inside a longer word).
    """
    values = {facts[name]: name for name in rt.PLACEHOLDERS}
    pattern = re.compile("(?<![A-Za-z0-9])(" + "|".join(re.escape(v) for v in sorted(values, key=len, reverse=True)) + ")(?![A-Za-z0-9])")
    return pattern.sub(lambda m: "{" + values[m.group(1)] + "}", paragraph)


def _check_report(facts, lang, text, summary_source):
    problems = []
    if not isinstance(text, str) or not text.strip():
        return [f"{lang}: the report is missing or empty"]
    if len(text) > MAX_REPORT_LENGTH:
        return [f"{lang}: the report is longer than {MAX_REPORT_LENGTH} characters"]
    if unicodedata.normalize("NFKC", text) != text:
        problems.append(f"{lang}: the report has characters that change when normalised (look-alike or ligature letters)")
    if not _REPORT_CHARS.fullmatch(text):
        bad = next(ch for ch in text if not _REPORT_CHARS.fullmatch(ch))
        problems.append(f"{lang}: the report contains the character {_shown(bad)}, which is not allowed")
    if "{" in text or "}" in text:
        problems.append(f"{lang}: a brace is left in the finished report")

    lines = text.split("\n")
    labels = rt.LABELS[lang]
    expected = rt.labelled_lines(facts, lang)
    expected_lines = {line for _, line in expected}
    for name, line in expected:
        count = lines.count(line)
        if count == 0:
            problems.append(f"{lang}: required field {name} is missing or has a different value than facts.json")
        elif count > 1:
            problems.append(f"{lang}: required field {name} appears more than once")
    prefixes = tuple(f"{labels[name]}:" for name in rt.FIELD_LINES + ("status", "summary"))
    for line in lines:
        if line.startswith(prefixes) and line not in expected_lines and line != f"{labels['summary']}:":
            problems.append(f"{lang}: a labelled line appears more than once or has a value that is not in the facts ({_shown(line, 60)})")
    for name in ("heading", "law", "footer"):
        if lines.count(labels[name]) != 1:
            problems.append(f"{lang}: the fixed line {name} must appear exactly once")
    if lines.count(f"{labels['summary']}:") != 1:
        problems.append(f"{lang}: the fixed line summary must appear exactly once")

    source_lines = {labels["source_ai"]: "ai", labels["source_code"]: "code"}
    found_sources = [source_lines[line] for line in lines if line in source_lines]
    if len(found_sources) != 1 or (summary_source is not None and found_sources[0] != summary_source):
        problems.append(f"{lang}: the summary source line is missing, doubled or not the expected one")

    reference = extract_tokens("\n".join(render_facts(facts, lang).values()))
    for kind, tokens in extract_tokens(text).items():
        for token in sorted(tokens - reference[kind]):
            problems.append(f"{lang}: the {kind} {_shown(token, 80)} is not in the facts")

    # The report must be exactly what the template writes: nothing added, nothing changed.
    summary_at = lines.index(f"{labels['summary']}:") if lines.count(f"{labels['summary']}:") == 1 else None
    if summary_at is not None and summary_at + 1 < len(lines) and len(found_sources) == 1:
        paragraph = lines[summary_at + 1]
        try:
            rebuilt = rt.render_report(facts, lang, paragraph, found_sources[0])
        except FactsError as error:
            problems.append(f"{lang}: the summary paragraph is not acceptable ({_shown(str(error), 80)})")
        else:
            if rebuilt != text:
                first = next((i for i, (a, b) in enumerate(zip(rebuilt.split("\n"), lines), 1) if a != b), "end")
                problems.append(f"{lang}: the report is not exactly what the template writes from the facts (first difference: line {first})")
        _, _, paragraph_problems = _check_paragraph(_unfill(paragraph, facts), lang)
        problems += [f"summary paragraph: {p}" for p in paragraph_problems]
    else:
        problems.append(f"{lang}: the report does not have the fixed summary structure")
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
        first = check_paragraphs(paragraphs)
        if not first.ok:
            return first
        reports = {lang: rt.render_report(facts, lang, rt.fill_placeholders(first.texts[lang], facts), summary_source)
                   for lang in LANGUAGES}
        second = check_reports(facts, reports, summary_source)
        return CheckResult(second.problems, first.texts, reports if second.ok else None)
    except FactsError as error:
        return CheckResult([f"the draft could not be written: {error}"])
    except Exception as error:  # a crash must never look like a pass
        return CheckResult([f"the check failed unexpectedly ({type(error).__name__})"])
