"""The approved sentences of the summary paragraph: the ONE table that the prompt, the fact checker and the fallback use.

Why whole sentences: no checker can judge the *meaning* of free text (a list of forbidden words, or even a list of
allowed words, still lets a false sentence through). So the AI may only CHOOSE from sentences that a human wrote and
checked. Every sentence is true for every product and every case, in German and English, and has its placeholders in a
fixed role. Nothing here says anything about impact, fixes, risk, time, or the state of the document (draft, approved, sent):
that belongs only to the heading and footer written by code.

Rules for a summary paragraph (checked by `fact_checker`):
    - it is made only of approved sentences, written exactly as in this table (white space may differ),
    - one to five different sentences, in the order of this table, and the first one is always "contains",
    - German and English use the same sentence ids,
    - only sentences that apply to the reason ("kev" or "evidence_file") of the case.
"""

from src.report_facts import LANGUAGES

PLACEHOLDERS = ("product_name", "component", "cve_id")  # the only words in braces that a sentence may hold
MAX_SENTENCES = 5

# (id, applies_to, {language: sentence}) - the ORDER of this list is the only allowed order.
SENTENCES = (
    ("contains", ("kev", "evidence_file"), {
        "en": "{product_name} contains the component {component}.",
        "de": "{product_name} enthält die Komponente {component}.",
    }),
    ("listed", ("kev", "evidence_file"), {
        "en": "The component {component} is listed with the vulnerability {cve_id}.",
        "de": "Die Komponente {component} ist mit der Schwachstelle {cve_id} gelistet.",
    }),
    ("kev", ("kev",), {
        "en": "A public list of known exploited vulnerabilities names {cve_id}.",
        "de": "In einer öffentlichen Liste bekannter ausgenutzter Schwachstellen wird {cve_id} genannt.",
    }),
    ("evidence", ("evidence_file",), {
        "en": "A human evidence file states that {cve_id} is exploited.",
        "de": "Eine menschliche Nachweisdatei besagt, dass {cve_id} ausgenutzt wird.",
    }),
    ("human_check", ("kev", "evidence_file"), {
        "en": "A human must check each statement before anything is reported.",
        "de": "Ein Mensch muss jede Aussage prüfen, bevor etwas gemeldet wird.",
    }),
)
IDS = tuple(sid for sid, _, _ in SENTENCES)
REASONS = ("kev", "evidence_file")


def applicable(exploited_via):
    """[(id, {language: sentence})] that may be used for a case with this reason, in the allowed order."""
    if exploited_via not in REASONS:
        raise ValueError("unknown reason")
    return [(sid, text) for sid, applies, text in SENTENCES if exploited_via in applies]


def compose(ids, lang):
    """The paragraph (with placeholders) for a list of sentence ids."""
    table = {sid: text for sid, _, text in SENTENCES}
    return " ".join(table[sid][lang] for sid in ids)


def fallback_ids(exploited_via):
    """The fixed fallback: every sentence that applies. It always passes the checker."""
    return [sid for sid, _ in applicable(exploited_via)]


def parse(text, lang, exploited_via, fill=None):
    """Split a paragraph into approved sentences. Returns (ids, problems); ids is [] when there is any problem.

    `fill` (optional) turns a sentence with placeholders into its finished text, so a FINISHED report line can be
    parsed with the same rules. Matching is exact: a changed word, a missing full stop or extra text is a problem.
    """
    if lang not in LANGUAGES:
        return [], ["unknown language"]
    if not isinstance(text, str):
        return [], [f"{lang}: the paragraph is not text"]
    text = " ".join(text.split())  # tabs, double blanks and line breaks between sentences do not matter
    if not text:
        return [], [f"{lang}: the paragraph is empty"]
    # the text was collapsed above, so the sentences are collapsed the same way (a name may contain two blanks in a row)
    options = [(sid, " ".join((fill(sentence[lang]) if fill else sentence[lang]).split())) for sid, sentence in applicable(exploited_via)]
    ids, position = [], 0
    while position < len(text):
        for sid, sentence in options:
            if text.startswith(sentence, position) and (position + len(sentence) == len(text) or text[position + len(sentence)] == " "):
                ids.append(sid)
                position += len(sentence) + 1
                break
        else:
            snippet = ascii(text[position:position + 40])
            return [], [f"{lang}: the text is not an approved sentence (it starts at {snippet})"]
    problems = []
    if len(ids) > MAX_SENTENCES:
        problems.append(f"{lang}: more than {MAX_SENTENCES} sentences")
    if len(set(ids)) != len(ids):
        problems.append(f"{lang}: a sentence is used more than once")
    order = [sid for sid, _ in options]
    if ids != sorted(ids, key=order.index):
        problems.append(f"{lang}: the sentences are not in the allowed order")
    if ids and ids[0] != "contains":
        problems.append(f"{lang}: the first sentence must be the one that says what the product contains")
    return ([] if problems else ids), problems

