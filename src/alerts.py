"""Q1: desktop alerts after `cra run`. Plain, testable code decides WHEN to alert; nothing here uses the AI.

An alert is raised only for something NEW or URGENT:
  - a possible report case that was not alerted before,
  - an open case (draft not approved) whose deadline is less than 6 hours away, or already passed,
  - a source (KEV / OSV) that failed or was stale, or a run that failed.
What was already alerted is remembered in `alerts-state.json` (in the cache folder), so the same thing is not shown
every 4 hours. A missing or damaged state file means "nothing is remembered": the alerts come again (never silence).

SECURITY: the alert text is only FIXED WORDING plus values that passed a strict pattern (a CVE id, a case id, a fixed
source name, a number). Nothing from OSV, KEV, the SBOM or the config is copied into it.
Nothing is sent anywhere. Showing the notification is done by the `notify(title, body) -> bool` function that is handed in.
"""

import hashlib
import json
import os
import re
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src import cases, matcher, news_watcher, report_facts
from src.case_commands import _tool_deadline

SOON = timedelta(hours=6)
MAX_STATE_BYTES = 1_000_000
STATE_NAME = "alerts-state.json"
LOG_NAME = "alerts.log"
MAX_LOG_BYTES = 1_000_000  # a bigger log is moved to alerts.log.1 and a new one is started
MAX_LOG_IDS = 20
STATE_SCHEMA = 1
CASE_BUDGET_SECONDS = 20  # the scheduled run has a time limit

NEW_REPORT_CASE = "NEW_REPORT_CASE"
DEADLINE_SOON = "DEADLINE_SOON"
DEADLINE_PASSED = "DEADLINE_PASSED"
SOURCE_PROBLEM = "SOURCE_PROBLEM"
RUN_FAILED = "RUN_FAILED"
CASE_UNREADABLE = "CASE_UNREADABLE"
TEST = "TEST"
KIND_ORDER = (NEW_REPORT_CASE, DEADLINE_PASSED, DEADLINE_SOON, SOURCE_PROBLEM, RUN_FAILED, CASE_UNREADABLE)

# A source problem that goes on is shown again after this time (a quiet, broken download must not stay forgotten).
REPEAT_AFTER = {SOURCE_PROBLEM: timedelta(hours=24), RUN_FAILED: timedelta(hours=24),
                DEADLINE_PASSED: timedelta(hours=24), CASE_UNREADABLE: timedelta(hours=24)}

TITLE = "CRA Copilot alert"
SAFE_TEXT = re.compile(r"[A-Za-z0-9 .,:;()/-]{1,300}")  # no quote, no $, no backtick, no angle bracket, no newline
MAX_BODY = 280
MAX_NAMED = 5
KEY = re.compile(r"[a-z-]{1,20}:[A-Za-z0-9-]{1,40}(:[a-z-]{1,20})?")
CASE_ID = cases.CASE_ID
SOURCE_NAMES = {"kev": "KEV", "osv": "OSV"}
STATUS_WORDS = {"failed": "failed", "stale": "stale"}  # any other status text becomes "not ok"; the raw text is never used


@dataclass(frozen=True)
class Item:
    kind: str
    key: str
    cve: str = None
    case_id: str = None
    source: str = None
    status: str = None


# ---------------------------------------------------------------- the rules


def _digest(parts):
    return hashlib.sha256(json.dumps(parts, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()[:12]


def _report_items(product, report_findings):
    items, seen = [], set()
    for finding in report_findings or []:
        if not isinstance(finding, dict):
            continue
        parts = [str(product.get("manufacturer")), str(product.get("product_name")),
                 str(finding.get("component")), str(finding.get("version")), str(finding.get("exploited_cve"))]
        key = "report:" + _digest(parts)
        if key in seen:
            continue
        seen.add(key)
        cve = finding.get("exploited_cve")
        cve = cve if isinstance(cve, str) and matcher.CVE_PATTERN.fullmatch(cve) else None
        try:
            case_id = cases.make_case_id({"manufacturer": product["manufacturer"], "product_name": product["product_name"],
                                          "component": finding["component"], "version": finding["version"],
                                          "cve_id": finding["exploited_cve"]})
        except (KeyError, TypeError):
            case_id = None
        items.append(Item(NEW_REPORT_CASE, key, cve=cve, case_id=case_id))
    return items


def _source_items(kev_status, osv_status):
    items = []
    for name, status in (("kev", kev_status), ("osv", osv_status)):
        word = status.get("status") if isinstance(status, dict) else None
        if word == "ok":
            continue
        shown = STATUS_WORDS.get(word, "not ok")
        items.append(Item(SOURCE_PROBLEM, f"source:{name}:{shown.replace(' ', '-')}", source=SOURCE_NAMES[name], status=shown))
    return items


def _case_items(now, cases_root):
    """Open cases (not approved, or approved but changed since) near or past their deadline, and unreadable case folders."""
    items = []
    if cases_root is None:
        return items
    started = time.monotonic()
    found, unreadable = cases.list_cases(cases_root)
    for case in found:
        if time.monotonic() - started > CASE_BUDGET_SECONDS:
            items.append(Item(CASE_UNREADABLE, "unreadable:many"))
            break
        try:
            if cases.approval_state(case) == cases.STATUS_APPROVED:
                continue
            own = case.facts.get("deadline_utc")
            deadline = datetime.fromisoformat(own) if own else None
            tool_deadline = _tool_deadline(case.meta)
            known = [d for d in (deadline, tool_deadline) if d is not None]
            effective = min(known)  # the earlier one counts; no deadline at all raises and counts as unreadable
        except Exception:  # a case that cannot be judged must not stay silent
            items.append(Item(CASE_UNREADABLE, f"unreadable:{case.case_id}", case_id=case.case_id))
            continue
        if effective < now:
            items.append(Item(DEADLINE_PASSED, f"deadline-passed:{case.case_id}", case_id=case.case_id))
        elif effective - now < SOON:
            items.append(Item(DEADLINE_SOON, f"deadline-soon:{case.case_id}", case_id=case.case_id))
    for name in unreadable:
        if CASE_ID.fullmatch(name):
            items.append(Item(CASE_UNREADABLE, f"unreadable:{name}", case_id=name))
        else:
            items.append(Item(CASE_UNREADABLE, "unreadable:many"))
    return items


def collect(now, product, report_findings, cases_root, kev_status, osv_status, run_failed):
    """Everything that is worth an alert right now (whether or not it was alerted before)."""
    items = []
    if run_failed:
        items.append(Item(RUN_FAILED, "runfail:run"))
    else:
        items += _report_items(product, report_findings)
        items += _source_items(kev_status, osv_status)
    items += _case_items(now, cases_root)
    return items


# ---------------------------------------------------------------- the text


def _named(item):
    parts = []
    if item.cve and matcher.CVE_PATTERN.fullmatch(item.cve):
        parts.append(item.cve)
    if item.case_id and CASE_ID.fullmatch(item.case_id):
        parts.append(f"({item.case_id})" if parts else item.case_id)
    return " ".join(parts)


def build_message(kind, items):
    """(title, body): fixed wording plus validated ids. Always matches SAFE_TEXT and is at most MAX_BODY long."""
    if kind == TEST:
        return TITLE, "Test notification. If you can read this, alerts work on this computer."
    if kind == SOURCE_PROBLEM:
        names = [f"{item.source} ({item.status})" for item in items
                 if item.source in SOURCE_NAMES.values() and item.status in ("failed", "stale", "not ok")]
        return TITLE, "A data source failed or is stale: " + ", ".join(names) + ". Do not rely on the last run."
    if kind == RUN_FAILED:
        return TITLE, "The last run failed. Do not rely on it. Look at the run output."
    named = [text for text in (_named(item) for item in items) if text]
    shown = ", ".join(named[:MAX_NAMED])
    if len(named) > MAX_NAMED:
        shown += f" and {len(named) - MAX_NAMED} more"
    nameless = len(items) - len(named)
    if nameless > 0 and not shown:
        shown = f"{nameless} item(s)"
    elif nameless > 0:
        shown += f", {nameless} without an id"
    if kind == NEW_REPORT_CASE:
        text = f"New possible report case: {shown}. Check the 24-hour deadline."
    elif kind == DEADLINE_SOON:
        text = f"Open case with less than 6 hours left: {shown}. Approve it and submit by hand."
    elif kind == DEADLINE_PASSED:
        text = f"Open case is past the 24-hour deadline: {shown}. Report as soon as possible."
    elif kind == CASE_UNREADABLE:
        text = f"A case folder cannot be read: {shown or 'see the cases folder'}. Look at it by hand."
    else:
        raise ValueError("unknown alert kind")
    text = text[:MAX_BODY]
    if not SAFE_TEXT.fullmatch(text):  # cannot happen with validated parts; if it ever does, say something fixed
        text = "Something needs a human look. Run the tool and read its output."
    return TITLE, text


# ---------------------------------------------------------------- what was already alerted


def state_path(cache):
    return Path(cache) / STATE_NAME


def load_state(cache):
    """({key: time}, damaged). A missing file is a normal empty start; anything unreadable is also empty (so alerts
    come again) and reported as damaged."""
    path = state_path(cache)
    try:
        if not path.exists():
            return {}, False
        if not path.is_file() or path.stat().st_size > MAX_STATE_BYTES:
            return {}, True
        data = json.loads(path.read_text(encoding="utf-8"))
        alerted = data["alerted"]
        if data["schema"] != STATE_SCHEMA or not isinstance(alerted, dict):
            return {}, True
        out = {}
        for key, when in alerted.items():
            if not isinstance(key, str) or not KEY.fullmatch(key) or not isinstance(when, str):
                return {}, True
            parsed = datetime.fromisoformat(when)
            if parsed.utcoffset() is None:
                return {}, True
            out[key] = parsed.astimezone(timezone.utc)
        return out, False
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return {}, True


def save_state(cache, state):
    """Write the state file in one piece (write a temporary file, then replace). Returns False if it could not be saved."""
    folder = Path(cache)
    text = json.dumps({"schema": STATE_SCHEMA, "alerted": {k: v.isoformat() for k, v in sorted(state.items())}}, indent=1)
    temp = None
    try:
        folder.mkdir(parents=True, exist_ok=True)
        handle, temp = tempfile.mkstemp(prefix="alerts-state-", suffix=".tmp", dir=folder)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(temp, state_path(cache))
        return True
    except OSError:
        if temp:
            try:
                os.unlink(temp)
            except OSError:
                pass
        return False


def _is_due(item, state, now):
    when = state.get(item.key)
    if when is None or when > now:  # a time in the future is not a real memory (it could only silence the alert)
        return True
    repeat = REPEAT_AFTER.get(item.kind)
    return repeat is not None and now - when >= repeat


# ---------------------------------------------------------------- the log (every alert, also when the toast works)


def log_path(cache):
    return Path(cache) / LOG_NAME


def _log_ids(items):
    names = [text for text in (_named(item) for item in items) if text]
    for item in items:  # a failed source is named too (fixed names only)
        if item.source in SOURCE_NAMES.values() and item.status in ("failed", "stale", "not ok"):
            names.append(f"{item.source} ({item.status})")
    shown = ", ".join(names[:MAX_LOG_IDS])
    if len(names) > MAX_LOG_IDS:
        shown += f" and {len(names) - MAX_LOG_IDS} more"
    return shown or "-"


def log_line(now, kind, items, toast_shown):
    """One line: UTC time | Berlin time | kind | ids | toast result. Only validated values are in it."""
    utc = now.astimezone(timezone.utc)
    berlin = utc.astimezone(report_facts.BERLIN)
    kind = kind if kind in KIND_ORDER + (TEST,) else "UNKNOWN"
    return (f"{utc.strftime('%Y-%m-%dT%H:%M:%SZ')} | {berlin.strftime('%Y-%m-%d %H:%M')} {berlin.tzname()} Berlin | {kind} | "
            f"{_log_ids(items)} | toast: {'shown' if toast_shown else 'not shown'}")


def append_log(cache, now, kind, items, toast_shown):
    """Add one line to cache/alerts.log. True if it was written, False if not (never raises)."""
    try:
        path = log_path(cache)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if path.is_file() and path.stat().st_size > MAX_LOG_BYTES:
                os.replace(path, path.with_name(LOG_NAME + ".1"))
        except OSError:
            pass  # a log a little over the limit is better than no log
        line = log_line(now, kind, items, toast_shown) + "\n"
        try:
            if path.is_file() and path.stat().st_size > 0:
                with open(path, "rb") as stream:
                    stream.seek(-1, os.SEEK_END)
                    if stream.read(1) != b"\n":
                        line = "\n" + line  # a half-written last line must not swallow this one
        except OSError:
            pass
        with open(path, "a", encoding="utf-8", newline="\n") as stream:
            stream.write(line)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- the whole step after a run


def after_run(now, cache, cases_root, product, report_findings, kev_status, osv_status, run_failed, notify, say=print):
    """Decide, show and remember. Never raises: a broken alert step must not change the result of the run."""
    try:
        return _after_run(now, cache, cases_root, product, report_findings, kev_status, osv_status, run_failed, notify, say)
    except Exception as error:  # the alert step is a help; the run result and exit code stay as they are
        say(f"(The alert step failed: {type(error).__name__}. Look at the run output yourself.)")
        return []


def _after_run(now, cache, cases_root, product, report_findings, kev_status, osv_status, run_failed, notify, say):
    items = collect(now, product, report_findings, cases_root, kev_status, osv_status, run_failed)
    state, damaged = load_state(cache)
    if damaged:
        say("(The alert memory file was damaged, so everything that is urgent is alerted again.)")
    due = [item for item in items if _is_due(item, state, now)]
    delivered = []
    for kind in KIND_ORDER:
        group = [item for item in due if item.kind == kind]
        if not group:
            continue
        title, body = build_message(kind, group)
        say(f"ALERT: {body}")
        shown = _show(notify, title, body)
        logged = append_log(cache, now, kind, group, shown)
        if not logged:
            say("(The alert could not be written to " + LOG_NAME + ".)")
        if not shown:
            say("(The desktop notification could not be shown; the alert is in " + LOG_NAME + " in the cache folder.)" if logged
                else "(The desktop notification could not be shown either, so this alert will come again at the next run.)")
        if shown or logged:  # remembered only when a human can find it somewhere
            for item in group:
                state[item.key] = now
            delivered.append((kind, len(group)))
    # forget what is no longer true, so it alerts again if it comes back
    active = {item.key for item in items}
    prefixes = ("deadline-soon", "deadline-passed", "unreadable") if run_failed else (
        "report", "deadline-soon", "deadline-passed", "unreadable", "source", "runfail")
    state = {key: when for key, when in state.items() if key in active or key.split(":")[0] not in prefixes}
    if not save_state(cache, state):
        say("(The alert memory file could not be saved, so the same alerts may come again.)")
    return delivered


_override = None  # tests only: a fake notifier that replaces the real one


def set_override(function):
    """Tests only. None switches the fake off again."""
    global _override
    _override = function


def default_notifier():
    """The notifier a normal run uses (tests replace it, so a test can never show a real notification)."""
    if _override is not None:
        return _override
    from src import toast  # here, not at the top: toast.py uses this file's text pattern
    return toast.show


def _show(notify, title, body):
    try:
        return bool(notify(title, body))
    except Exception:  # whatever goes wrong with the notification, the run goes on
        return False
