"""Part 4 (first half): build the facts of one possible report case, and format them for people.

`facts` is a small plain dict (it becomes facts.json). Everything a report says about the product comes from here.
The ONE formatter in this file turns facts into German and English text. The template, the AI paragraph filler
and the fact checker all use these same strings, so they can never disagree.

Rules (CLAUDE.md trust rules 1 and 2):
    - Only code decides. A finding must already be a REPORT_CASE made by the matcher.
    - The CVE id is the one that matched the KEV list or the human evidence file, never text from an advisory.
    - Every value is checked again with a strict pattern, because the finding may come from a saved file.
"""

import re
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from src.matcher import CVE_PATTERN, DATE_PATTERN, read_evidence
from src.news_watcher import KEV_URL
from src.sbom_reader import EU_MEMBER_STATES, MAX_TEXT_LENGTH, NAME_PATTERN, PRODUCT_NAME_PATTERN, VERSION_PATTERN

try:
    BERLIN = ZoneInfo("Europe/Berlin")  # Windows has no time-zone database of its own: the tzdata package supplies it
except ZoneInfoNotFoundError as error:  # pragma: no cover - only without the tzdata package
    raise RuntimeError("the time zone database is missing: install tzdata (pip install -r requirements.txt)") from error

LANGUAGES = ("de", "en")
SCHEMA = 1
AWARENESS_WINDOW = timedelta(hours=24)  # CRA Art. 14(2)(a): early warning within 24 hours of becoming aware

NOTIFICATION_TYPE_TEXT = {"de": "Schwachstelle", "en": "Vulnerability"}
AWARENESS_PLACEHOLDER = {
    "de": "[NOCH NICHT FESTGELEGT - ein Mensch muss den Zeitpunkt bestätigen]",
    "en": "[NOT SET YET - a human must confirm the time]",
}
DEADLINE_PLACEHOLDER = {
    "de": "[Zeitpunkt des Bewusstwerdens + 24 Stunden, sobald dieser festgelegt ist]",
    "en": "[awareness time + 24 hours, once that time is set]",
}
_EN_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")  # no locale: fixed
_DE_ZONE_NAMES = {"CET": "MEZ", "CEST": "MESZ"}

MAX_STATES = len(EU_MEMBER_STATES)

# A link in a legal report: plain https, a real host name, no user@host trick, no quotes, no $, no stray %.
_HOST = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
REPORT_LINK = re.compile(r"https://" + _HOST + r"(?:/(?:[A-Za-z0-9._~:/?#=&+,-]|%[0-9A-Fa-f]{2})*)?")
MAX_LINK_LENGTH = 500
FACT_KEYS = {"schema", "notification_type", "manufacturer", "product_name", "member_states", "component", "version",
             "cve_id", "cve_matched_on", "exploited_via", "evidence", "awareness_time_utc", "deadline_utc", "title"}


class FactsError(ValueError):
    """The input is not a clean possible report case, or a value cannot be shown safely."""


# ---------------------------------------------------------------- the one formatter


def _check_language(lang):
    if lang not in LANGUAGES:
        raise FactsError("unknown language")


def _parse_aware(text):
    if not isinstance(text, str):
        raise FactsError("a time must be text")
    try:
        value = datetime.fromisoformat(text)
        if value.utcoffset() is None:
            raise FactsError("a time needs a time zone")
        return value.astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:  # OverflowError: a year at the very edge of the calendar
        raise FactsError("not a valid time") from error


def _day(value, lang):
    return f"{value.day:02d}.{value.month:02d}.{value.year}" if lang == "de" else f"{value.day:02d} {_EN_MONTHS[value.month - 1]} {value.year}"


def format_date(text, lang):
    """A date-only fact (YYYY-MM-DD): 20.10.2026 or 20 Oct 2026."""
    _check_language(lang)
    if not isinstance(text, str) or not DATE_PATTERN.fullmatch(text):
        raise FactsError("not a valid date")
    try:
        return _day(date.fromisoformat(text), lang)
    except ValueError as error:
        raise FactsError("not a valid date") from error


def format_time(text, lang):
    """A stored UTC time shown in Berlin time AND in UTC, so the clock change can never hide an hour."""
    _check_language(lang)
    utc = _parse_aware(text)
    try:
        berlin = utc.astimezone(BERLIN)
    except (OverflowError, ValueError) as error:  # the last day of year 9999 does not fit once Berlin is one hour ahead
        raise FactsError("the time is outside the supported calendar") from error
    zone = berlin.tzname()
    clock = f"{berlin.hour:02d}:{berlin.minute:02d}"
    utc_part = f"{_day(utc, lang)} {utc.hour:02d}:{utc.minute:02d} UTC"
    if lang == "de":
        return f"{_day(berlin, lang)}, {clock} Uhr (Berlin, {_DE_ZONE_NAMES.get(zone, zone)}) = {utc_part}"
    return f"{_day(berlin, lang)}, {clock} (Berlin, {zone}) = {utc_part}"


def render_facts(facts, lang):
    """Every required field as text in one language. The single source of strings for template and checker."""
    _check_language(lang)
    validate_facts(facts)  # facts.json may have been edited: never trust it blindly
    evidence = facts["evidence"]
    evidence_text = evidence["url"]
    if evidence["date"]:
        evidence_text += f" ({format_date(evidence['date'], lang)})"
    return {
        "notification_type": NOTIFICATION_TYPE_TEXT[lang],
        "title": facts["title"][lang],
        "manufacturer": facts["manufacturer"],
        "product_name": facts["product_name"],
        "component": facts["component"],
        "version": facts["version"],
        "cve_id": facts["cve_id"],
        "awareness": format_time(facts["awareness_time_utc"], lang) if facts["awareness_time_utc"] else AWARENESS_PLACEHOLDER[lang],
        "deadline": format_time(facts["deadline_utc"], lang) if facts["deadline_utc"] else DEADLINE_PLACEHOLDER[lang],
        "member_states": ", ".join(facts["member_states"]),
        "evidence": evidence_text,
    }


# ---------------------------------------------------------------- building facts


def _text(value, pattern, what):
    if not isinstance(value, str) or not value or len(value) > MAX_TEXT_LENGTH or not pattern.fullmatch(value):
        raise FactsError(f"{what} is missing or has invalid characters")
    return value


def _titles(product_name, component, version, cve_id):
    return {
        "en": f"Possible actively exploited vulnerability {cve_id} in {component} {version} ({product_name})",
        "de": f"Mögliche aktiv ausgenutzte Schwachstelle {cve_id} in {component} {version} ({product_name})",
    }


def _link(url):
    if not isinstance(url, str) or len(url) > MAX_LINK_LENGTH or not REPORT_LINK.fullmatch(url):
        raise FactsError("the evidence link is not a plain https link (no user name, quotes or special characters)")
    return url


def _evidence(finding, cve_id, kev_ids, evidence_dir):
    """The evidence of the case. It is checked against the real KEV list / the real evidence file, not the saved run."""
    via = finding.get("exploited_via")
    if via == "kev":
        if not isinstance(kev_ids, (set, frozenset)) or cve_id not in kev_ids:
            raise FactsError("the CVE id is not in the saved KEV list")
        return {"kind": "kev", "url": KEV_URL, "date": None}
    if via == "evidence_file":
        saved = finding.get("evidence")
        real = read_evidence(evidence_dir, cve_id) if evidence_dir is not None else None
        if real is None or not isinstance(saved, dict) or saved != real:
            raise FactsError("the human evidence file for this CVE is missing, unusable or different from the run record")
        format_date(real["date"], "en")  # raises FactsError for anything but a real date
        return {"kind": "human_evidence", "url": _link(real["source_url"]), "date": real["date"]}
    raise FactsError("the finding is not marked as exploited by KEV or by a human evidence file")


def build_facts(product, finding, kev_ids, evidence_dir=None, awareness=None):
    """Facts of ONE possible report case.

    `product` is the product config (manufacturer, product_name, member_states), `finding` one matcher finding.
    `kev_ids` is the set of CVE ids of the saved KEV list: a KEV-based CVE id must be in it (no list = refused).
    `evidence_dir`: a human-evidence-based CVE id must have a usable file there that equals the run record.
    `awareness` is an aware datetime set by a human (Phase 4); without it the report shows a clear placeholder.
    """
    if not isinstance(product, dict) or not isinstance(finding, dict):
        raise FactsError("product and finding must be objects")
    if finding.get("action") != "REPORT_CASE" or finding.get("status") != "AFFECTED" or finding.get("exploited") is not True:
        raise FactsError("only an AFFECTED and exploited finding (REPORT_CASE) can become a report")

    # The CVE id is the one that matched KEV / the evidence file. Advisory ids and texts are never used.
    cve_id = finding.get("exploited_cve")
    if not isinstance(cve_id, str) or not CVE_PATTERN.fullmatch(cve_id):
        raise FactsError("the exploited CVE id is missing or malformed")
    listed = finding.get("cve_ids")
    if not isinstance(listed, list) or cve_id not in listed:
        raise FactsError("the exploited CVE id is not one of the finding's CVE ids")
    evidence = _evidence(finding, cve_id, kev_ids, evidence_dir)

    awareness_utc = deadline_utc = None
    if awareness is not None:
        if not isinstance(awareness, datetime) or awareness.utcoffset() is None:
            raise FactsError("the awareness time needs a time zone")
        try:
            awareness_utc = awareness.astimezone(timezone.utc)
            deadline_utc = (awareness_utc + AWARENESS_WINDOW).isoformat()  # 24 real hours, not "same clock time tomorrow"
        except OverflowError as error:
            raise FactsError("the awareness time is outside the supported calendar") from error
        awareness_utc = awareness_utc.isoformat()

    states = product.get("member_states")
    facts = {
        "schema": SCHEMA,
        "notification_type": "vulnerability",
        "manufacturer": product.get("manufacturer"),
        "product_name": product.get("product_name"),
        "member_states": list(states) if isinstance(states, list) else states,
        "component": finding.get("component"),
        "version": finding.get("version"),
        "cve_id": cve_id,
        "cve_matched_on": finding.get("exploited_cve_matched_on"),
        "exploited_via": finding.get("exploited_via"),
        "evidence": evidence,
        "awareness_time_utc": awareness_utc,
        "deadline_utc": deadline_utc,
        "title": None,
    }
    if all(isinstance(facts[k], str) for k in ("product_name", "component", "version")):
        facts["title"] = _titles(facts["product_name"], facts["component"], facts["version"], cve_id)
    # Every other check (names, versions, states, link, times, title ...) lives in validate_facts, in ONE place.
    validate_facts(facts)
    return facts


def validate_facts(facts):
    """Check a facts dict again from scratch (it may have been read from an edited facts.json)."""
    if not isinstance(facts, dict) or set(facts) != FACT_KEYS or facts["schema"] != SCHEMA:
        raise FactsError("facts have an unexpected shape")
    if facts["notification_type"] != "vulnerability":
        raise FactsError("unknown type of notification")
    _text(facts["manufacturer"], PRODUCT_NAME_PATTERN, "manufacturer")
    _text(facts["product_name"], PRODUCT_NAME_PATTERN, "product name")
    _text(facts["component"], NAME_PATTERN, "component name")
    _text(facts["version"], VERSION_PATTERN, "component version")
    states = facts["member_states"]
    if (not isinstance(states, list) or not states or len(states) > MAX_STATES
            or not all(isinstance(s, str) and s in EU_MEMBER_STATES for s in states) or len(set(states)) != len(states)):
        raise FactsError("member_states must be a non-empty list of different EU country codes")
    if not isinstance(facts["cve_id"], str) or not CVE_PATTERN.fullmatch(facts["cve_id"]):
        raise FactsError("the CVE id is malformed")
    if facts["cve_matched_on"] not in ("id", "alias", "upstream"):
        raise FactsError("it is not known where the CVE link came from")
    evidence = facts["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != {"kind", "url", "date"}:
        raise FactsError("the evidence has an unexpected shape")
    if facts["exploited_via"] == "kev":
        if evidence != {"kind": "kev", "url": KEV_URL, "date": None}:
            raise FactsError("the KEV evidence is not the fixed KEV link")
    elif facts["exploited_via"] == "evidence_file":
        if evidence["kind"] != "human_evidence":
            raise FactsError("the evidence kind does not fit")
        _link(evidence["url"])
        format_date(evidence["date"], "en")
    else:
        raise FactsError("the finding is not marked as exploited by KEV or by a human evidence file")
    if (facts["awareness_time_utc"] is None) != (facts["deadline_utc"] is None):
        raise FactsError("awareness time and deadline must be set together")
    if facts["awareness_time_utc"] is not None:
        awareness = _parse_aware(facts["awareness_time_utc"])
        try:
            expected_deadline = (awareness + AWARENESS_WINDOW).isoformat()
        except OverflowError as error:
            raise FactsError("the awareness time is outside the supported calendar") from error
        if facts["awareness_time_utc"] != awareness.isoformat() or facts["deadline_utc"] != expected_deadline:
            raise FactsError("the deadline is not exactly 24 hours after the awareness time (stored in UTC)")
    if facts["title"] != _titles(facts["product_name"], facts["component"], facts["version"], facts["cve_id"]):
        raise FactsError("the title does not match the facts")


# Words that make a *name* read like a statement about the case. A real product may be called "SafeGuard Router", so a name
# is never refused for this; the preview only warns, so a human looks at the wording.
_CLAIM_WORDS = re.compile(
    r"approved|sent|submitted|reported|safe|secure|fixed|patched|critical|harmless|unaffected|not affected|"
    r"evidence file|exploited|enisa|csirt|"
    r"freigegeben|gesendet|gemeldet|sicher|behoben|kritisch|harmlos|nicht betroffen|unbetroffen|ausgenutzt"
)
_CVE_IN_NAME = re.compile(r"cve[ -]?\d{4}")
_LOOK_ALIKE_DIGITS = str.maketrans("013457@$", "oieastas")


def claim_word_warnings(facts):
    """[field names] whose text reads like a statement (approved, sent, safe, not affected, a CVE id ...).

    Blanks, hyphens, upper case and simple digit-for-letter swaps (N0t Affected, Appr0ved) are ignored when matching.
    """
    found = []
    for name in ("manufacturer", "product_name", "component", "version"):
        value = facts.get(name)
        if not isinstance(value, str):
            continue
        plain = " ".join(re.sub(r"[-_]+", " ", value.lower().translate(_LOOK_ALIKE_DIGITS)).split())
        if _CLAIM_WORDS.search(plain) or _CVE_IN_NAME.search(value.lower()):
            found.append(name)
    return found
