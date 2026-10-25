"""Part 3: is a component affected? is the vulnerability actively exploited?

Plain, testable code decides this. The AI never does (CLAUDE.md rule 1).

Every check gives one of three answers:
    AFFECTED, NOT_AFFECTED, UNKNOWN
"I do not know" is never turned into "safe". Every answer records the RULE that gave it.
Versions are NEVER compared as plain text ("1.10" would wrongly come before "1.9").
NOT_AFFECTED is only given when we really evaluated something that says so.
"""

import json
import re
from datetime import date
from pathlib import Path

from packageurl import PackageURL
from packaging.version import InvalidVersion, Version

from src.safe_paths import safe_join

REPORT_CASE_LABEL = "POSSIBLE REPORT CASE (a human decides if it is reportable under the CRA)"  # what people read; the action name stays REPORT_CASE

AFFECTED = "AFFECTED"
NOT_AFFECTED = "NOT_AFFECTED"
UNKNOWN = "UNKNOWN"

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,12}")
DATE_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
PLAIN_VERSION = re.compile(r"[0-9]+(\.[0-9]+)*")
# A Maven limit like 2.0-beta9 counts as "just below 2.0".
PRE_RELEASE_LIMIT = re.compile(r"([0-9]+(?:\.[0-9]+)*)-(?:alpha|beta|rc|m)[0-9]*", re.IGNORECASE)
EVIDENCE_URL = re.compile(r"https://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{4,500}")

MAX_NUMBER_DIGITS = 9  # absurdly long version numbers are not compared
MAX_EVENTS = 10_000
MAX_VERSIONS = 20_000


def _list(value):
    """Return value if it is a list, else an empty list (odd shapes never crash a run)."""
    return value if isinstance(value, list) else []


# ---------------------------------------------------------------- versions


def normalize_pypi_name(name):
    """PEP 503: lowercase, and runs of - _ . count as one dash."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _numbers(text):
    parts = text.split(".")
    if any(len(p) > MAX_NUMBER_DIGITS for p in parts):
        return None
    numbers = [int(p) for p in parts]
    while numbers and numbers[-1] == 0:  # 2.0 == 2.0.0
        numbers.pop()
    return tuple(numbers)


def maven_version_key(version):
    """Sort key for a plain-number Maven version like 2.14.1, or None if it is anything else."""
    if not isinstance(version, str) or not PLAIN_VERSION.fullmatch(version):
        return None
    numbers = _numbers(version)
    return None if numbers is None else (numbers, 0)


def maven_limit_key(limit):
    """Sort key for a range limit. 2.0-beta9 / -rc / -alpha / -m count as just below 2.0."""
    key = maven_version_key(limit)
    if key is not None:
        return key
    if isinstance(limit, str):
        match = PRE_RELEASE_LIMIT.fullmatch(limit)
        if match:
            numbers = _numbers(match.group(1))
            if numbers is not None:
                return (numbers, -1)
    return None


def _pypi_version(text):
    """Parse a PyPI version. A local build tag (1.0+abc) is dropped: it is still release 1.0."""
    try:
        return Version(Version(text).public) if isinstance(text, str) else None
    except InvalidVersion:
        return None


# ---------------------------------------------------------------- ranges


def _intervals(events, parse):
    """Turn OSV range events into [(start, end, end_inclusive)], whatever order they come in.

    Returns None if a limit cannot be read or the events do not make sense.
    """
    events = _list(events)
    if len(events) > MAX_EVENTS:
        return None
    parsed = []  # (version key, 0 = start / 1 = end, is_inclusive_end)
    for event in events:
        if not isinstance(event, dict):
            return None
        for kind in ("introduced", "fixed", "last_affected"):
            if kind in event:
                key = parse(event[kind])
                if key is None:
                    return None
                parsed.append((key, 0 if kind == "introduced" else 1, kind == "last_affected"))
    # Sort by version only. Python's sort is stable, so events at the SAME version keep the order they were
    # written in: "fixed 2.0" then "introduced 2.0" means affected again from 2.0 on. (Forcing starts first
    # used to swallow the re-introduction.) A tie written in an odd order ends as "end without a start" = UNKNOWN.
    parsed.sort(key=lambda item: item[0])
    intervals = []
    for position, (key, is_end, inclusive) in enumerate(parsed):
        if not is_end:
            if intervals and intervals[-1][1] is None:
                if any(later[0] == key and later[1] for later in parsed[position + 1:]):
                    return None  # "introduced X" before "fixed X" inside an open range: the order is ambiguous
                continue  # already inside an open interval: the earlier start is the one that counts
            intervals.append([key, None, False])
        else:
            if not intervals or intervals[-1][1] is not None:
                return None  # an end without a start does not make sense
            intervals[-1][1] = key
            intervals[-1][2] = inclusive
    return intervals


def _in_intervals(key, intervals):
    for start, end, inclusive in intervals:
        if key < start:
            continue
        if end is None or key < end or (inclusive and key == end):
            return True
    return False


def _usable_ranges(entry):
    return [r for r in _list(entry.get("ranges")) if isinstance(r, dict) and r.get("type") == "ECOSYSTEM"]


def _unsupported_range_types(entries):
    return {
        r.get("type")
        for e in entries
        for r in _list(e.get("ranges"))
        if isinstance(r, dict) and r.get("type") != "ECOSYSTEM"
    }


def _check_entry(entry, key, in_exact_list, parse_limit):
    """Shared range logic. Returns (status, rule_prefix_result) for one OSV 'affected' entry."""
    if in_exact_list:
        return AFFECTED, "osv_exact_version_list"
    evaluated = bool(_list(entry.get("versions")))
    unreadable = False
    for rng in _usable_ranges(entry):
        intervals = _intervals(rng.get("events"), parse_limit)
        if intervals is None:
            unreadable = True
            continue
        if intervals:
            evaluated = True
        if _in_intervals(key, intervals):
            return AFFECTED, "range"
    if unreadable:
        return UNKNOWN, "range_limit_not_comparable"
    if not evaluated:
        return UNKNOWN, "no_usable_range"  # nothing to check against must never mean "safe"
    return NOT_AFFECTED, "range" if _usable_ranges(entry) else "not_in_osv_version_list"


def _check_entry_maven(entry, version):
    versions = _list(entry.get("versions"))
    if len(versions) > MAX_VERSIONS:
        return UNKNOWN, "version_list_too_long"
    if version in versions:
        return AFFECTED, "osv_exact_version_list"
    key = maven_version_key(version)
    if key is None:
        return UNKNOWN, "maven_version_not_comparable"
    status, rule = _check_entry(entry, key, False, maven_limit_key)
    return status, {"range": "maven_numeric_range"}.get(rule, rule)


def _check_entry_pypi(entry, version):
    parsed = _pypi_version(version)
    if parsed is None:
        return UNKNOWN, "pypi_version_not_readable"
    listed_versions = _list(entry.get("versions"))
    if len(listed_versions) > MAX_VERSIONS:
        return UNKNOWN, "version_list_too_long"
    in_list = any(_pypi_version(listed) == parsed for listed in listed_versions)
    status, rule = _check_entry(entry, parsed, in_list, _pypi_version)
    return status, {"range": "pypi_range"}.get(rule, rule)


# ---------------------------------------------------------------- one component + one vulnerability


def _package_identity(purl):
    """Return (ecosystem, name, version). Raises ValueError for anything we do not support."""
    parsed = PackageURL.from_string(purl)
    if parsed.type == "maven" and parsed.namespace and parsed.name and parsed.version:
        return "maven", f"{parsed.namespace}:{parsed.name}", parsed.version
    if parsed.type == "pypi" and parsed.name and parsed.version:
        return "pypi", normalize_pypi_name(parsed.name), parsed.version
    raise ValueError("unsupported package")


def _entry_matches(entry, ecosystem, name):
    package = entry.get("package")
    if not isinstance(package, dict):
        return False
    their_name = package.get("name")
    if not isinstance(their_name, str):
        return False
    if ecosystem == "maven":
        return package.get("ecosystem") == "Maven" and their_name == name
    return package.get("ecosystem") == "PyPI" and normalize_pypi_name(their_name) == name


def match_vulnerability(purl, record, osv_listed):
    """Is the component `purl` affected by the OSV `record`? Returns (status, rule).

    osv_listed: True when OSV itself listed this vulnerability for this purl.
    """
    try:
        ecosystem, name, version = _package_identity(purl)
    except ValueError:
        return UNKNOWN, "unsupported_package"
    if not isinstance(record, dict):
        return UNKNOWN, "record_malformed"
    entries = [e for e in _list(record.get("affected")) if isinstance(e, dict) and _entry_matches(e, ecosystem, name)]
    if not entries:
        if osv_listed:
            return UNKNOWN, "osv_listed_it_but_package_not_found_in_record"
        return NOT_AFFECTED, "package_not_in_record"

    check = _check_entry_maven if ecosystem == "maven" else _check_entry_pypi
    results = [check(entry, version) for entry in entries]
    if record.get("truncated") is True and not any(status == AFFECTED for status, _ in results):
        return UNKNOWN, "record_truncated"  # part of the record was cut off: "not affected" cannot be trusted

    for status, rule in results:
        if status == AFFECTED:
            return AFFECTED, rule
    for status, rule in results:
        if status == UNKNOWN:
            return UNKNOWN, rule
    unsupported = _unsupported_range_types(entries)
    if unsupported:  # e.g. a GIT or SEMVER range we cannot evaluate: do not call it safe
        return UNKNOWN, "git_range_not_supported" if "GIT" in unsupported else "range_type_not_supported"
    if osv_listed:
        return UNKNOWN, "osv_says_affected_but_our_check_disagrees"
    return NOT_AFFECTED, results[0][1]


# ---------------------------------------------------------------- exploited?


def cve_ids_of(record):
    """CVE ids of a record, with where each came from: [(cve, "id" | "alias" | "upstream")]."""
    found = {}
    sources = [("id", [record.get("id")]), ("alias", _list(record.get("aliases"))), ("upstream", _list(record.get("upstream")))]
    for origin, values in sources:
        for value in values:
            if isinstance(value, str):
                cve = value.strip().upper()
                if CVE_PATTERN.fullmatch(cve) and cve not in found:
                    found[cve] = origin
    return sorted(found.items())


def read_evidence(evidence_dir, cve_id, today=None):
    """Return the human-written evidence for a CVE, or None.

    A file `evidence/<CVE>.json` needs a "source_url" (https) and a "date" (YYYY-MM-DD, not in the future).
    """
    if evidence_dir is None or not CVE_PATTERN.fullmatch(cve_id):
        return None
    try:
        path = safe_join(evidence_dir, f"{cve_id}.json")
        if not path.is_file():
            return None
        with open(path, "rb") as handle:
            raw = handle.read(65537)
        if len(raw) > 65536:
            return None
        data = json.loads(raw.decode("utf-8-sig"))
        url = data["source_url"]
        text_date = data["date"]
        if not isinstance(text_date, str) or not DATE_PATTERN.fullmatch(text_date):
            return None
        day = date.fromisoformat(text_date)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):  # ValueError also covers an unsafe name
        return None
    if day > (today or date.today()):
        return None
    if not isinstance(url, str) or not EVIDENCE_URL.fullmatch(url):
        return None
    return {"source_url": url, "date": day.isoformat()}


def invalid_evidence_cves(record, evidence_dir):
    """CVEs of this record for which a human evidence file EXISTS but cannot be used (broken, no link...).

    A human wrote "this is exploited"; we must not silently treat that as "not exploited".
    """
    if evidence_dir is None:
        return []
    problems = []
    for cve, _ in cve_ids_of(record):
        try:
            exists = safe_join(evidence_dir, f"{cve}.json").exists()
        except (OSError, ValueError):
            exists = False
        if exists and read_evidence(evidence_dir, cve) is None:
            problems.append(cve)
    return problems


def exploited_status(record, kev_ids, evidence_dir=None):
    """Return (exploited, via, cve, matched_on). Only KEV or a human evidence file can say yes.

    matched_on tells where the CVE id came from ("id", "alias" or "upstream"), so a human can see
    if the link to the CVE rests only on an alias.
    """
    cves = cve_ids_of(record)
    for cve, origin in cves:
        if cve in kev_ids:
            return True, "kev", cve, origin
    for cve, origin in cves:
        if read_evidence(evidence_dir, cve):
            return True, "evidence_file", cve, origin
    return False, None, None, None


def action_for(status, exploited, exploited_known=True):
    """What happens next. exploited_known=False means we could not check if it is exploited."""
    if status == AFFECTED and exploited:
        return "REPORT_CASE"
    if status == UNKNOWN and exploited:
        return "URGENT_HUMAN_REVIEW"
    if status == AFFECTED:
        return "RECORD" if exploited_known else "URGENT_HUMAN_REVIEW"
    if status == UNKNOWN:
        return "HUMAN_REVIEW" if exploited_known else "URGENT_HUMAN_REVIEW"
    return "NONE"


# ---------------------------------------------------------------- all components


def _finding(component, vuln_id, status, rule, exploited=False, via=None, cve=None, matched_on=None,
             cves=(), exploited_known=True, evidence=None, evidence_problem=()):
    return {
        "component": component.name,
        "version": component.version,
        "purl": component.purl,
        "ecosystem": component.ecosystem,
        "vulnerability_id": vuln_id,
        "cve_ids": [c for c, _ in cves],
        "status": status,
        "rule": rule,
        "exploited": exploited,
        "exploited_known": exploited or exploited_known,
        "exploited_via": via,
        "exploited_cve": cve,
        "exploited_cve_matched_on": matched_on,
        "evidence": evidence,  # link + date of the human evidence, so the decision can be traced
        "evidence_problem": list(evidence_problem),  # CVEs with an evidence file that could not be used
        "action": action_for(status, exploited, exploited or exploited_known),
    }


def evaluate(components, feeds, evidence_dir=None):
    """Check all components against the downloaded data.

    Returns {"checked", "findings", "ignored_withdrawn", "ignored_withdrawn_ids", "packages",
             "kev_status", "evidence_folder_given"}.

    If the KEV list could not be downloaded fresh, "not in the list" is NOT the same as
    "not exploited": such findings get exploited_known = False and go to urgent human review.
    """
    kev_ok = feeds.kev_status.get("status") == "ok"
    findings = []
    ignored = []
    checked = 0
    for component in components:
        if component.status != "OK":
            findings.append(_finding(component, None, UNKNOWN, f"component_unknown: {component.reason}",
                                     exploited_known=kev_ok))
            continue
        checked += 1
        vuln_ids = feeds.purl_vulns.get(component.purl)
        if not isinstance(vuln_ids, list):
            # No CVE list was obtained, so nothing was compared with KEV: "exploited?" is NOT known.
            findings.append(_finding(component, None, UNKNOWN, "osv_gave_no_answer", exploited_known=False))
            continue
        for vuln_id in vuln_ids:
            record = feeds.vulns.get(vuln_id)
            if not isinstance(record, dict):
                findings.append(_finding(component, vuln_id, UNKNOWN, "osv_details_missing", exploited_known=False))
                continue
            if record.get("withdrawn"):
                ignored.append(vuln_id)
                continue
            try:
                status, rule = match_vulnerability(component.purl, record, osv_listed=True)
                exploited, via, cve, matched_on = exploited_status(record, feeds.kev_ids, evidence_dir)
                cves = cve_ids_of(record)
                evidence = read_evidence(evidence_dir, cve) if via == "evidence_file" else None
                bad_evidence = [] if exploited else invalid_evidence_cves(record, evidence_dir)
            except (TypeError, AttributeError, ValueError, KeyError, OverflowError, RecursionError):
                findings.append(_finding(component, vuln_id, UNKNOWN, "record_malformed", exploited_known=False))
                continue
            findings.append(_finding(component, vuln_id, status, rule, exploited, via, cve, matched_on,
                                     cves, exploited_known=kev_ok and not bad_evidence,
                                     evidence=evidence, evidence_problem=bad_evidence))
    return {
        "checked": checked,
        "findings": findings,
        "ignored_withdrawn": len(ignored),
        "ignored_withdrawn_ids": ignored,
        "packages": summarize_packages(findings),
        "data_gaps": sum(1 for f in findings if f["rule"] in DATA_GAP_RULES),
        "kev_status": feeds.kev_status.get("status"),
        "evidence_folder_given": evidence_dir is not None,
    }


# Findings that mean "the data could not be read or was cut off": the run is then INCOMPLETE.
DATA_GAP_RULES = {
    "osv_gave_no_answer", "osv_details_missing", "record_malformed", "record_truncated", "version_list_too_long",
}

_ORDER = {AFFECTED: 2, UNKNOWN: 1, NOT_AFFECTED: 0}


def summarize_packages(findings):
    """One answer per package: if ANY version of it is AFFECTED, the package counts as AFFECTED."""
    packages = {}
    for finding in findings:
        if finding["purl"] is None:
            continue
        try:
            ecosystem, name, _ = _package_identity(finding["purl"])
        except ValueError:
            continue
        key = f"{ecosystem}:{name}"
        if _ORDER[finding["status"]] >= _ORDER[packages.get(key, NOT_AFFECTED)]:
            packages[key] = finding["status"]
    return packages
