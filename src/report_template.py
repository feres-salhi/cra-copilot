"""Part 4 (second half): the fixed German + English early-warning template.

Code writes every fact and every label. The AI only supplies the short summary paragraph at the end.
All strings for facts come from `report_facts.render_facts`, the same strings the fact checker compares with.
The report is plain text. Nothing here sends anything (CLAUDE.md rule 6).
"""

import re

from src.report_facts import FactsError, LANGUAGES, render_facts, validate_facts
from src.summary_sentences import PLACEHOLDERS

_STATUS_FIELD = re.compile(r"@(component|version|cve)")
_PLACEHOLDER = re.compile(r"\{(" + "|".join(PLACEHOLDERS) + r")\}")

MAX_PARAGRAPH_LENGTH = 1000

LABELS = {
    "en": {
        "heading": "EARLY WARNING - DRAFT (NOT APPROVED, NOT SENT)",
        "law": "CRA Article 14(2)(a): early warning of a possible actively exploited vulnerability",
        "notification_type": "Type of notification",
        "title": "Title",
        "manufacturer": "Manufacturer",
        "product_name": "Product",
        "component": "Affected component",
        "cve_id": "Vulnerability ID (CVE)",
        "awareness": "Awareness time",
        "deadline": "Calculated deadline (awareness time + 24 hours)",
        "member_states": "EU Member States where the product is made available",
        "evidence": "Source",
        "status": "Assessment",
        "summary": "Summary",
        "source_ai": "Summary text: written by an AI and checked by code. A human must read it.",
        "source_code": "Summary text: fixed wording written by code (the AI was not used or its text was rejected).",
        "footer": "This is a draft. A human must check and approve it. Nothing has been sent.",
    },
    "de": {
        "heading": "FRÜHWARNUNG - ENTWURF (NICHT FREIGEGEBEN, NICHT GESENDET)",
        "law": "CRA Artikel 14 Absatz 2 Buchstabe a: Frühwarnung vor einer möglicherweise aktiv ausgenutzten Schwachstelle",
        "notification_type": "Art der Meldung",
        "title": "Titel",
        "manufacturer": "Hersteller",
        "product_name": "Produkt",
        "component": "Betroffene Komponente",
        "cve_id": "Schwachstellen-ID (CVE)",
        "awareness": "Zeitpunkt des Bewusstwerdens",
        "deadline": "Berechnete Frist (Zeitpunkt des Bewusstwerdens + 24 Stunden)",
        "member_states": "EU-Mitgliedstaaten, in denen das Produkt bereitgestellt wird",
        "evidence": "Quelle",
        "status": "Einordnung",
        "summary": "Zusammenfassung",
        "source_ai": "Text der Zusammenfassung: von einer KI geschrieben und per Code geprüft. Ein Mensch muss ihn lesen.",
        "source_code": "Text der Zusammenfassung: feste Formulierung, vom Code geschrieben (die KI wurde nicht genutzt oder ihr Text wurde abgelehnt).",
        "footer": "Dies ist ein Entwurf. Ein Mensch muss ihn prüfen und freigeben. Es wurde nichts gesendet.",
    },
}

_STATUS = {
    ("en", "kev"): ("According to the product's software list (SBOM), the component @component @version is listed as affected by @cve. "
                    "The vulnerability is listed as exploited in the CISA Known Exploited Vulnerabilities (KEV) list. "),
    ("en", "evidence_file"): ("According to the product's software list (SBOM), the component @component @version is listed as affected by @cve. "
                              "A human evidence file states that the vulnerability is exploited. "),
    ("de", "kev"): ("Laut Software-Stückliste (SBOM) des Produkts ist die Komponente @component @version von @cve betroffen. "
                    "Die Schwachstelle ist in der Liste der Known Exploited Vulnerabilities (KEV) der CISA als ausgenutzt aufgeführt. "),
    ("de", "evidence_file"): ("Laut Software-Stückliste (SBOM) des Produkts ist die Komponente @component @version von @cve betroffen. "
                              "Eine menschliche Nachweisdatei besagt, dass die Schwachstelle ausgenutzt wird. "),
}
_WEAK_LINK = {
    ("en", "alias"): "The link between the advisory and this CVE rests on an alias. ",
    ("en", "upstream"): "The link between the advisory and this CVE rests on an upstream reference. ",
    ("de", "alias"): "Die Verknüpfung zwischen Hinweis und dieser CVE beruht auf einem Alias. ",
    ("de", "upstream"): "Die Verknüpfung zwischen Hinweis und dieser CVE beruht auf einem Upstream-Verweis. ",
}
_CLOSING = {
    "en": "The tool did not verify that the vulnerability is exploited in this product. A human decides whether it is reportable under the CRA.",
    "de": "Das Werkzeug hat nicht geprüft, ob die Schwachstelle in diesem Produkt ausgenutzt wird. Ein Mensch entscheidet, ob sie nach dem CRA meldepflichtig ist.",
}


def fill_placeholders(paragraph, facts):
    """Replace {product_name}, {component} and {cve_id} in ONE pass (a filled value is never looked at again)."""
    if not isinstance(paragraph, str):
        raise FactsError("the summary paragraph must be text")
    validate_facts(facts)
    return _PLACEHOLDER.sub(lambda match: facts[match.group(1)], paragraph)


def status_sentence(facts, lang):
    """The fixed sentence that says why this is a possible report case (the same words the checker expects)."""
    if lang not in LANGUAGES:
        raise FactsError("unknown language")
    validate_facts(facts)
    text = _STATUS[(lang, facts["exploited_via"])] + _WEAK_LINK.get((lang, facts["cve_matched_on"]), "") + _CLOSING[lang]
    # one pass, not str.format and not chained replace: a fact value is never looked at again
    values = {"component": facts["component"], "version": facts["version"], "cve": facts["cve_id"]}
    return _STATUS_FIELD.sub(lambda match: values[match.group(1)], text)


# The labelled lines, in order. The fact checker reads this same list, so template and checker cannot drift apart.
FIELD_LINES = ("notification_type", "title", "manufacturer", "product_name", "component", "cve_id", "awareness",
               "deadline", "member_states", "evidence")


def labelled_lines(facts, lang):
    """[(field, "Label: value"), ...] for every required line of the report, in the order they are written."""
    if lang not in LANGUAGES:
        raise FactsError("unknown language")
    label = LABELS[lang]
    value = render_facts(facts, lang)
    result = []
    for field in FIELD_LINES:
        text = f"{value['component']} {value['version']}" if field == "component" else value[field]
        result.append((field, f"{label[field]}: {text}"))
    result.append(("status", f"{label['status']}: {status_sentence(facts, lang)}"))
    return result


SUMMARY_SOURCES = ("ai", "code")


def render_report(facts, lang, paragraph, summary_source="code"):
    """The full early warning draft in one language. `paragraph` has its placeholders filled already.

    `summary_source` says who wrote the paragraph: "ai" (checked by code) or "code" (fixed wording).
    """
    if lang not in LANGUAGES:
        raise FactsError("unknown language")
    if summary_source not in SUMMARY_SOURCES:
        raise FactsError("unknown summary source")
    # One single printable line: a paragraph can never start a new labelled line (a forged deadline or "approved" line).
    if (not isinstance(paragraph, str) or not paragraph.strip() or len(paragraph) > MAX_PARAGRAPH_LENGTH
            or not paragraph.isprintable() or "{" in paragraph or "}" in paragraph):
        raise FactsError("the summary paragraph must be one short printable line without braces")
    label = LABELS[lang]
    line = dict(labelled_lines(facts, lang))
    lines = [label["heading"], label["law"], ""]
    lines += [line[field] for field in FIELD_LINES]
    lines += ["", line["status"], "", f"{label['summary']}:", paragraph, label["source_" + summary_source], "", label["footer"]]
    return "\n".join(lines) + "\n"
