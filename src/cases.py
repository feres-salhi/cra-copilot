"""Phase 4: the case data model. One folder per possible report case: cases/<case-id>/

    facts.json   the facts of the case (built by code, see report_facts.py)
    draft.md     the German + English draft in ONE plain-text file (never shown as a web page)
    check.json   what the fact checker said when the draft was made (information only: `cra approve` checks again)
    case.json    the status (PENDING / APPROVED), where the case came from, and the human's awareness entry

The case id is checked against a strict pattern BEFORE any file path is built (PLAN.md risk 8).
Nothing in this file sends anything (CLAUDE.md rule 6).
"""

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import re

from src.report_facts import FactsError, LANGUAGES, validate_facts
from src.safe_paths import safe_join

CASE_ID = re.compile(r"case-[0-9a-f]{12}")
MAX_FILE_BYTES = 1_000_000
MAX_LISTED_CASES = 1000
SCHEMA = 1
STATUS_PENDING = "PENDING"
STATUS_APPROVED = "APPROVED"
STATUSES = (STATUS_PENDING, STATUS_APPROVED)
EN_MARK = "=== ENGLISH ==="
DE_MARK = "=== DEUTSCH ==="
APPROVAL_KEYS = {"approver", "approved_at", "draft_sha256", "facts_sha256", "sbom_sha256"}
CASE_FILES = ("facts.json", "draft.md", "check.json", "case.json")


class CaseError(Exception):
    """A case cannot be created or read safely."""


class CaseExists(CaseError):
    """There is already a case for these facts."""


# ---------------------------------------------------------------- ids and paths


def check_case_id(text):
    """The case id, or CaseError. Strict: `case-` and 12 lower-case hex characters, nothing else."""
    if not isinstance(text, str) or not CASE_ID.fullmatch(text):
        raise CaseError("a case id looks like case-0123456789ab (case- and 12 characters 0-9 a-f)")
    return text


def case_path(root, case_id):
    check_case_id(case_id)
    try:
        return safe_join(root, case_id)
    except ValueError as error:
        raise CaseError("the case folder is outside the cases folder") from error


def make_case_id(facts):
    """The same product, component, version and CVE always give the same id (so one case is not drafted twice)."""
    key = [facts["manufacturer"], facts["product_name"], facts["component"], facts["version"], facts["cve_id"]]
    digest = hashlib.sha256(json.dumps(key, separators=(",", ":")).encode("utf-8")).hexdigest()
    return "case-" + digest[:12]


# ---------------------------------------------------------------- the draft file


def join_draft(reports):
    """draft.md: the English and the German report, each under a fixed marker line."""
    return f"{EN_MARK}\n{reports['en']}{DE_MARK}\n{reports['de']}"


def split_draft(text):
    """The inverse of join_draft. Anything that is not exactly that shape is refused."""
    if not isinstance(text, str) or not text.startswith(EN_MARK + "\n") or text.count(f"\n{DE_MARK}\n") != 1:
        raise CaseError("draft.md does not have the fixed shape (English part, German part)")
    english, german = text[len(EN_MARK) + 1:].split(f"\n{DE_MARK}\n")
    reports = {"en": english + "\n", "de": german}
    if not reports["en"].strip() or not reports["de"].strip() or EN_MARK in text[len(EN_MARK):] or join_draft(reports) != text:
        raise CaseError("draft.md does not have the fixed shape (English part, German part)")
    return reports


# ---------------------------------------------------------------- writing


def new_meta(created_at, origin):
    """The start of case.json: status PENDING, nobody has approved anything."""
    return {"schema": SCHEMA, "status": STATUS_PENDING, "created_at": created_at.isoformat(), "origin": origin,
            "approval": None}


def _json_text(data):
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def _write_text(path, text):
    """Write the file in one piece (temp file, then rename); UTF-8 with plain line ends."""
    handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as temp:
            temp.write(text.encode("utf-8"))
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def create_case(root, facts, reports, check, source, meta):
    """Create cases/<id>/ with the four files. Returns the case id.

    Refuses facts without an awareness time, a draft that did not pass the fact check, and an id that already exists.
    A crash while writing removes the half-written folder.
    """
    try:
        validate_facts(facts)
    except FactsError as error:
        raise CaseError(f"the facts are not valid: {error}") from error
    if facts["awareness_time_utc"] is None:
        raise CaseError("a case needs an awareness time that a human confirmed")
    if not getattr(check, "ok", False) or not isinstance(reports, dict) or set(reports) != set(LANGUAGES):
        raise CaseError("the draft did not pass the fact check: no case is created")
    if not isinstance(meta, dict) or meta.get("status") != STATUS_PENDING:
        raise CaseError("a new case starts with the status PENDING")
    if not all(isinstance(reports[lang], str) for lang in LANGUAGES) or split_draft(join_draft(reports)) != reports:
        raise CaseError("the reports cannot be stored: they do not survive writing and reading again")
    case_id = make_case_id(facts)
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    folder = case_path(root, case_id)
    if folder.exists():
        raise CaseExists(f"the case {case_id} already exists")
    safe_source = {"mode": source.get("mode"), "reason": source.get("reason")}
    check_data = {**check.as_dict(), "source": safe_source,
                  "note": "information only: `cra approve` runs the fact check again and ignores this file"}
    # Build the whole case in a folder whose name is not a case id, then rename it in ONE step:
    # a crash leaves only an ignorable temp folder, never a half case that blocks the id.
    temp = Path(tempfile.mkdtemp(dir=root, prefix=".tmp-"))
    try:
        _write_text(temp / "facts.json", _json_text(facts))
        _write_text(temp / "draft.md", join_draft(reports))
        _write_text(temp / "check.json", _json_text(check_data))
        _write_text(temp / "case.json", _json_text(meta))
        try:
            os.rename(temp, folder)
        except OSError as error:
            if folder.exists():
                raise CaseExists(f"the case {case_id} already exists") from error
            raise
    except BaseException:
        for leftover in temp.iterdir() if temp.is_dir() else ():
            try:
                leftover.unlink()
            except OSError:
                pass
        try:
            temp.rmdir()
        except OSError:
            pass
        raise
    return case_id


def save_meta(root, case_id, meta):
    """Replace case.json of an existing case (used when a human approves)."""
    folder = case_path(root, case_id)
    if not folder.is_dir() or folder.is_symlink():
        raise CaseError("the case does not exist")
    _check_meta(meta)
    current = _json_file(_read_file(folder, "case.json"), "case.json")
    _check_meta(current)
    if meta["status"] == STATUS_PENDING and current["status"] != STATUS_PENDING:
        raise CaseError("an approved case can never go back to PENDING by writing case.json")
    _write_text(folder / "case.json", _json_text(meta))


# ---------------------------------------------------------------- reading


@dataclass
class Case:
    case_id: str
    folder: Path
    facts: dict
    reports: dict
    check: dict
    meta: dict
    sha256: dict = field(default_factory=dict)  # of the exact bytes on disk: draft, facts, check, case


def _read_file(folder, name):
    path = folder / name
    try:
        if not path.is_file():
            raise CaseError(f"{name} is missing")
        with open(path, "rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError as error:
        raise CaseError(f"{name} cannot be read") from error
    if len(raw) > MAX_FILE_BYTES:
        raise CaseError(f"{name} is too large")
    return raw


def _json_file(raw, name):
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as error:
        raise CaseError(f"{name} is not valid JSON") from error
    if not isinstance(data, dict):
        raise CaseError(f"{name} is not a JSON object")
    return data


def _check_meta(meta):
    if meta.get("schema") != SCHEMA or meta.get("status") not in STATUSES:
        raise CaseError("case.json has an unknown shape or status")
    if not isinstance(meta.get("origin"), dict):
        raise CaseError("case.json has no origin")
    approval = meta.get("approval")
    if meta["status"] == STATUS_APPROVED:
        if (not isinstance(approval, dict) or set(approval) != APPROVAL_KEYS
                or not all(isinstance(approval[k], str) and approval[k] for k in APPROVAL_KEYS)
                or not all(len(approval[k]) == 64 for k in ("draft_sha256", "facts_sha256", "sbom_sha256"))):
            raise CaseError("case.json says APPROVED but the approval record is incomplete")
    if meta["status"] == STATUS_PENDING and approval is not None:
        raise CaseError("case.json says PENDING but has an approval record")
    try:
        datetime.fromisoformat(meta["created_at"])
    except (KeyError, TypeError, ValueError) as error:
        raise CaseError("case.json has no valid creation time") from error


def load_case(root, case_id):
    """Read and check one case. Every file is size-capped and re-validated; the facts must belong to this id."""
    folder = case_path(root, case_id)
    if folder.is_symlink() or not folder.is_dir():
        raise CaseError("the case does not exist")
    raw = {name: _read_file(folder, name) for name in CASE_FILES}
    facts = _json_file(raw["facts.json"], "facts.json")
    try:
        validate_facts(facts)
    except FactsError as error:
        raise CaseError(f"facts.json is not valid: {error}") from error
    if facts["awareness_time_utc"] is None or make_case_id(facts) != case_id:
        raise CaseError("facts.json does not belong to this case id")
    try:
        text = raw["draft.md"].decode("utf-8")
    except UnicodeDecodeError as error:
        raise CaseError("draft.md is not UTF-8 text") from error
    reports = split_draft(text)
    check = _json_file(raw["check.json"], "check.json")
    meta = _json_file(raw["case.json"], "case.json")
    _check_meta(meta)
    sha256 = {key: hashlib.sha256(raw[name]).hexdigest()
              for key, name in (("draft", "draft.md"), ("facts", "facts.json"), ("check", "check.json"), ("case", "case.json"))}
    return Case(case_id, folder, facts, reports, check, meta, sha256)


def list_cases(root):
    """([Case, ...], [ids that could not be read]) for every case folder. A missing cases folder is simply empty."""
    root = Path(root)
    try:
        names = sorted(entry.name for entry in os.scandir(root) if CASE_ID.fullmatch(entry.name))
    except OSError:
        return [], []
    found, unreadable = [], []
    for name in names[:MAX_LISTED_CASES]:
        try:
            found.append(load_case(root, name))
        except CaseError:
            unreadable.append(name)
    return found, unreadable
