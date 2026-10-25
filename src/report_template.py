"""Part 4 (second half): the fixed German + English early-warning template.

Code writes every fact and every label. The AI only supplies the short summary paragraph at the end.
All strings for facts come from `report_facts.render_facts`, the same strings the fact checker compares with.
The report is plain text. Nothing here sends anything (CLAUDE.md rule 6).
"""

import re

from src.report_facts import FactsError, LANGUAGES, render_facts, validate_facts

PLACEHOLDERS = ("product_name", "component", "cve_id")  # the only words the AI paragraph may use in braces
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
    # plain replacement, not str.format: no brace in a fact can ever do anything
    return text.replace("@component", facts["component"]).replace("@version", facts["version"]).replace("@cve", facts["cve_id"])


def render_report(facts, lang, paragraph):
    """The full early warning draft in one language. `paragraph` has its placeholders filled already."""
    if lang not in LANGUAGES:
        raise FactsError("unknown language")
    # One single printable line: a paragraph can never start a new labelled line (a forged deadline or "approved" line).
    if (not isinstance(paragraph, str) or not paragraph.strip() or len(paragraph) > MAX_PARAGRAPH_LENGTH
            or not paragraph.isprintable() or "{" in paragraph or "}" in paragraph):
        raise FactsError("the summary paragraph must be one short printable line without braces")
    label = LABELS[lang]
    value = render_facts(facts, lang)
    component_line = f"{value['component']} {value['version']}"
    lines = [
        label["heading"],
        label["law"],
        "",
        f"{label['notification_type']}: {value['notification_type']}",
        f"{label['title']}: {value['title']}",
        f"{label['manufacturer']}: {value['manufacturer']}",
        f"{label['product_name']}: {value['product_name']}",
        f"{label['component']}: {component_line}",
        f"{label['cve_id']}: {value['cve_id']}",
        f"{label['awareness']}: {value['awareness']}",
        f"{label['deadline']}: {value['deadline']}",
        f"{label['member_states']}: {value['member_states']}",
        f"{label['evidence']}: {value['evidence']}",
        "",
        f"{label['status']}: {status_sentence(facts, lang)}",
        "",
        f"{label['summary']}:",
        paragraph,
        "",
        label["footer"],
    ]
    return "\n".join(lines) + "\n"
