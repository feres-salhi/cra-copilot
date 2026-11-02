"""Phase 4: the awareness time. A human types it (legal "awareness" cannot be computed); the tool checks it against what
the tool itself observed (PLAN.md section (i), item 1).

    - It may not be in the future.
    - It may not be earlier than the data allowed: for a KEV case the start of the day the CVE was added to the KEV list,
      for a human-evidence case the date of the evidence file.
    - If it is LATER than the first saved run that found the case, a loud warning is shown and a typed reason is needed,
      because a deadline counted from a later time would be silently late.
    - If the 24 hours have already passed, a loud warning is shown (a late report is still better than none).
"""

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from src import news_watcher
from src.report_facts import AWARENESS_WINDOW, BERLIN

MAX_RUN_FILES = 5000  # most run files looked at when searching for the first run of a case
MAX_RUN_FILE_BYTES = 2 * 1024 * 1024  # real run records are small; bigger files are skipped in this search
EARLIEST_OFFSET = timezone(timedelta(hours=14))  # a calendar date starts here first (UTC+14)

_INPUT = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}) (UTC|Z|Berlin|[+-][0-9]{2}:[0-9]{2})")
_ISO = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})(Z|[+-][0-9]{2}:[0-9]{2})")  # ISO 8601, no seconds
FORMAT_HELP = ("Type the time like this:  2026-11-02 09:30 Berlin   (or UTC, or an offset such as +01:00). "
               "Year-month-day, hour:minute (24-hour clock), then the time zone. "
               "ISO 8601 also works, for example 2026-11-02T01:50+01:00 or 2026-11-02T01:50Z (a time zone is always needed).")


class AwarenessError(ValueError):
    """The typed time is not usable. The message is safe to show."""


def parse_awareness(text):
    """What the human typed -> an aware datetime in UTC. Strict: two fixed formats (the typed one and ISO 8601 with T), a zone is always needed."""
    if not isinstance(text, str) or len(text) > 100:
        raise AwarenessError("that is not a time. " + FORMAT_HELP)
    match = _INPUT.fullmatch(text.strip()) or _ISO.fullmatch(text.strip())
    if not match:
        raise AwarenessError("that is not a time in the expected format. " + FORMAT_HELP)
    year, month, day, hour, minute = (int(v) for v in match.groups()[:5])
    zone = match.group(6)
    try:
        if zone in ("UTC", "Z"):
            return datetime(year, month, day, hour, minute, tzinfo=timezone.utc)
        if zone == "Berlin":
            return _berlin(year, month, day, hour, minute)
        hours, minutes = int(zone[1:3]), int(zone[4:6])
        total = hours * 60 + minutes
        if minutes > 59 or (zone[0] == "+" and total > 14 * 60) or (zone[0] == "-" and total > 12 * 60):
            raise AwarenessError("that time zone offset is not possible")
        offset = timedelta(hours=hours, minutes=minutes) * (1 if zone[0] == "+" else -1)
        return datetime(year, month, day, hour, minute, tzinfo=timezone(offset)).astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:
        if isinstance(error, AwarenessError):
            raise
        raise AwarenessError("that date or time does not exist") from error


def _berlin(year, month, day, hour, minute):
    first = datetime(year, month, day, hour, minute, tzinfo=BERLIN, fold=0)
    as_utc = first.astimezone(timezone.utc)
    if as_utc.astimezone(BERLIN).replace(tzinfo=None) != first.replace(tzinfo=None):
        raise AwarenessError("that Berlin time does not exist (the clock jumps forward that night)")
    if first.utcoffset() != first.replace(fold=1).utcoffset():
        raise AwarenessError("that Berlin time happens twice (the clock goes back that night): "
                             "type it with an offset instead, +02:00 (summer time) or +01:00 (winter time)")
    return as_utc


# ---------------------------------------------------------------- what the data allows


def earliest_allowed(exploited_via, cve_id, kev_data, evidence_date):
    """(earliest allowed awareness time, why). Taken from the saved KEV list or the human evidence file.

    The date has no time zone, so it is read as the first moment that calendar date exists anywhere (UTC+14):
    that never refuses a real time near midnight.
    """
    if exploited_via == "kev":
        entries = kev_data.get("vulnerabilities") if isinstance(kev_data, dict) else None
        if not isinstance(entries, list):
            raise AwarenessError("the saved KEV list is missing, so the earliest allowed time cannot be checked")
        for entry in entries:
            if isinstance(entry, dict) and entry.get("cveID") == cve_id:
                try:
                    day = date.fromisoformat(entry.get("dateAdded"))
                except (TypeError, ValueError) as error:
                    raise AwarenessError("the KEV date for this CVE is not readable") from error
                return datetime(day.year, day.month, day.day, tzinfo=EARLIEST_OFFSET).astimezone(timezone.utc), f"KEV dateAdded {day.isoformat()}"
        raise AwarenessError("this CVE is not in the saved KEV list")
    if exploited_via == "evidence_file":
        try:
            day = date.fromisoformat(evidence_date)
        except (TypeError, ValueError) as error:
            raise AwarenessError("the date of the human evidence is not readable") from error
        return datetime(day.year, day.month, day.day, tzinfo=EARLIEST_OFFSET).astimezone(timezone.utc), f"date of the human evidence {day.isoformat()}"
    raise AwarenessError("the case is not marked as exploited by KEV or by human evidence")


# ---------------------------------------------------------------- the first run that found the case


def _case_in_run(run, product_name, component, version, cve_id):
    product = run.get("product")
    result = run.get("result")
    if not isinstance(product, dict) or product.get("product_name") != product_name or not isinstance(result, dict):
        return False
    findings = result.get("findings")
    if not isinstance(findings, list):
        return False
    return any(isinstance(f, dict) and f.get("action") == "REPORT_CASE" and f.get("component") == component
               and f.get("version") == version and f.get("exploited_cve") == cve_id for f in findings)


def find_first_found(runs_dir, product_name, component, version, cve_id, extra_run_files=()):
    """(started_at, file name) of the oldest SEALED run record that contains this possible report case, or None.

    Unsealed, unreadable or foreign records are skipped. `extra_run_files` are looked at too (the run used for drafting
    may lie outside the runs folder).
    """
    files = []
    try:
        files = sorted(p for p in Path(runs_dir).glob("*.json") if p.is_file())[:MAX_RUN_FILES]
    except OSError:
        pass
    files += [Path(p) for p in extra_run_files]
    best = None
    for path in files:
        try:
            if path.stat().st_size > MAX_RUN_FILE_BYTES:
                continue
        except OSError:
            continue
        run, problem = news_watcher.read_sealed_run(path)
        if run is None or not _case_in_run(run, product_name, component, version, cve_id):
            continue
        started = news_watcher._parse_time(run.get("started_at"))
        if started is None:
            continue
        started = started.astimezone(timezone.utc)
        if best is None or started < best[0]:
            best = (started, path.name)
    return best


# ---------------------------------------------------------------- the check


@dataclass
class Observation:
    first_found_at: datetime | None
    first_found_file: str | None
    earliest_allowed: datetime
    earliest_reason: str


@dataclass
class Verdict:
    refusals: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    needs_reason: bool = False


def _span(delta):
    minutes = int(delta.total_seconds() // 60)
    hours, minutes = divmod(minutes, 60)
    parts = []
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes or not parts:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    return " ".join(parts)


def check_awareness(awareness, now, observation):
    """Compare the typed time with what the tool observed. See the module text for the rules."""
    if not isinstance(awareness, datetime) or awareness.utcoffset() is None:
        raise AwarenessError("the awareness time needs a time zone")
    verdict = Verdict()
    if awareness > now:
        verdict.refusals.append("The awareness time is in the future. You cannot be aware of something that has not happened yet.")
    if awareness < observation.earliest_allowed:
        verdict.refusals.append(f"The awareness time is earlier than the data allowed ({observation.earliest_reason}). "
                                "If you really knew earlier, put the earlier source into a human evidence file first.")
    if observation.first_found_at is None:
        verdict.warnings.append("No sealed run record that contains this case could be found in the runs folder, "
                                "so your time could not be compared with the first time this tool saw the case.")
    elif awareness > observation.first_found_at:
        later = _span(awareness - observation.first_found_at)
        verdict.needs_reason = True
        verdict.warnings.append(
            f"WARNING: your awareness time is LATER than the first run that found this case "
            f"({news_watcher.printable(observation.first_found_file, 80)}, started {observation.first_found_at.isoformat()}): {later} later. "
            "The 24-hour clock may already have been running since then, so the deadline below could be too late.")
    if not verdict.refusals and awareness + AWARENESS_WINDOW < now:
        verdict.warnings.append("WARNING: THE 24-HOUR DEADLINE HAS ALREADY PASSED. Report as soon as possible and "
                                "tell your CSIRT why it is late.")
    return verdict
