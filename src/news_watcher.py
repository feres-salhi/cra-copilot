"""Part 2: download public vulnerability data (OSV.dev and CISA KEV).

The most important rule of this file:
    A FAILED download must NEVER look like "nothing new".

Every source gets a status:
    ok      fresh, complete and checked data
    stale   we had to use an older saved copy
    failed  no usable data at all

All network traffic goes through one small function (`http_fetch`) so tests can
replace it with a fake and never touch the internet.
"""

import hashlib
import http.client
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from src.safe_paths import safe_join

# Fixed HTTPS addresses (never built from SBOM text).
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
ALLOWED_HOSTS = {"www.cisa.gov", "api.osv.dev"}

TIMEOUT_SECONDS = 30  # per network read
TOTAL_SECONDS = 120  # for one whole download
MAX_KEV_BYTES = 10 * 1024 * 1024
MAX_OSV_VULN_BYTES = 5 * 1024 * 1024
MAX_OSV_BATCH_BYTES = 20 * 1024 * 1024
MAX_CACHE_FILE_BYTES = 20 * 1024 * 1024
RETRIES = 3  # after the first try
BATCH_SIZE = 500  # OSV allows at most 1000 queries per batch
MAX_PAGE_ROUNDS = 20
MAX_KEV_DROP = 0.05  # the count may not drop by more than 5% below the highest count we have seen
STALE_AFTER_HOURS = 26

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,12}")
# Vulnerability IDs go into file names, so they must match a strict pattern first.
VULN_ID_PATTERN = re.compile(r"(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._-]{0,63}")  # no ".." anywhere


class FetchError(Exception):
    """A download failed. `status` is the HTTP status, or None for network problems."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def utc_now():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------- network


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FetchError(f"refusing to follow a redirect (HTTP {code})", code)


def http_fetch(url, body=None, max_bytes=MAX_OSV_VULN_BYTES):
    """Download `url` (POST when `body` is given). Returns the bytes of a 200 answer.

    Safety rules: https on port 443 only, only our two known hosts, certificate checks on
    (the Python default), a timeout per read and for the whole download, a size cap,
    no redirects, and an answer that is shorter than its Content-Length counts as failed.
    """
    parsed = urllib.parse.urlparse(url)
    try:
        port = parsed.port
    except ValueError:
        port = -1
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS or port not in (None, 443):
        raise FetchError("address is not on the allowed list")
    request = urllib.request.Request(url, data=body, method="POST" if body is not None else "GET")
    request.add_header("User-Agent", "cra-copilot (student project)")
    if body is not None:
        request.add_header("Content-Type", "application/json")
    opener = urllib.request.build_opener(_NoRedirects)
    deadline = time.monotonic() + TOTAL_SECONDS
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            expected = response.headers.get("Content-Length")
            chunks, size = [], 0
            while True:
                if time.monotonic() > deadline:
                    raise FetchError("download took too long")
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise FetchError("answer is larger than the size cap")
                chunks.append(chunk)
    except FetchError:
        raise
    except urllib.error.HTTPError as error:
        raise FetchError(f"HTTP {error.code}", error.code) from error
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as error:
        raise FetchError(f"network problem: {type(error).__name__}") from error
    if expected is not None and expected.isdigit() and int(expected) != size:
        raise FetchError("answer is shorter than announced (cut off)")
    return b"".join(chunks)


def _json_loads(data):
    try:
        return json.loads(data)
    except (ValueError, RecursionError) as error:
        raise FetchError("answer is not valid JSON") from error


def _fetch_json(fetch, sleep, url, body=None, max_bytes=MAX_OSV_VULN_BYTES):
    """Download and parse JSON. Retries on 429 / 5xx / network problems / cut-off (unreadable) answers."""
    delay = 1
    for attempt in range(RETRIES + 1):
        try:
            raw = fetch(url, body, max_bytes)
            return raw, _json_loads(raw)
        except FetchError as error:
            retryable = error.status is None or error.status == 429 or error.status >= 500
            if not retryable or attempt == RETRIES:
                raise
            sleep(delay)
            delay *= 2


# ---------------------------------------------------------------- saved files


def _write_json_atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temp, path)


def _read_json(path):
    try:
        if not path.is_file():
            return None
        with open(path, "rb") as handle:
            raw = handle.read(MAX_CACHE_FILE_BYTES + 1)
        if len(raw) > MAX_CACHE_FILE_BYTES:
            return None
        return json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, RecursionError):
        return None


def _parse_time(text):
    """Parse an ISO time that must carry a time zone. Returns an aware datetime or None."""
    try:
        value = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    return value if value.tzinfo is not None else None


# ---------------------------------------------------------------- CISA KEV


def validate_kev(data, saved_max_count=None, saved_released=None):
    """Return a problem text if the KEV data is not trustworthy, else None."""
    if not isinstance(data, dict):
        return "KEV data is not a JSON object"
    for key in ("catalogVersion", "dateReleased", "count", "vulnerabilities"):
        if key not in data:
            return f"KEV data is missing the field {key}"
    released = _parse_time(data["dateReleased"])
    if released is None:
        return "KEV dateReleased is not a valid time"
    entries = data["vulnerabilities"]
    if not isinstance(entries, list) or not entries:
        return "KEV vulnerability list is missing or empty"
    if not isinstance(data["count"], int) or isinstance(data["count"], bool):
        return "KEV count is not a number"
    if data["count"] != len(entries):
        return "KEV stated count does not match the real number of entries"
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            return "KEV entry is not an object"
        cve = entry.get("cveID")
        added = entry.get("dateAdded")
        if not isinstance(cve, str) or not CVE_PATTERN.fullmatch(cve):
            return "KEV entry has an invalid cveID"
        if cve in seen:
            return "KEV has the same cveID twice"
        seen.add(cve)
        try:
            date.fromisoformat(added)
        except (TypeError, ValueError):
            return "KEV entry has an invalid dateAdded"
    if saved_max_count and len(entries) < saved_max_count * (1 - MAX_KEV_DROP):
        return "KEV count dropped by more than 5% compared with the highest count seen before"
    saved_time = _parse_time(saved_released)
    if saved_time is not None and released < saved_time:
        return "KEV dateReleased is older than the saved copy (possible replay)"
    return None


def load_kev_cache(cache_dir):
    """Return (data, meta) of the saved KEV copy, or (None, None). Structure is re-checked."""
    saved = _read_json(Path(cache_dir) / "kev" / "kev-saved.json")
    if not isinstance(saved, dict) or not isinstance(saved.get("data"), dict):
        return None, None
    if validate_kev(saved["data"]) is not None:
        return None, None
    meta = {k: saved.get(k) for k in ("downloaded_at", "sha256", "max_count")}
    return saved["data"], meta


def fetch_kev(cache_dir, fetch=http_fetch, sleep=time.sleep, now=utc_now):
    """Download the KEV list. Returns (data_or_None, status_dict)."""
    saved, saved_meta = load_kev_cache(cache_dir)
    saved_meta = saved_meta or {}
    saved_max = max(
        len(saved["vulnerabilities"]) if saved else 0,
        saved_meta.get("max_count") if isinstance(saved_meta.get("max_count"), int) else 0,
    )
    try:
        raw, data = _fetch_json(fetch, sleep, KEV_URL, None, MAX_KEV_BYTES)
        problem = validate_kev(data, saved_max or None, saved["dateReleased"] if saved else None)
        if problem:
            raise FetchError(problem)
    except FetchError as error:
        if saved is not None:
            return saved, {
                "status": "stale",
                "detail": f"download failed ({error}); using the saved copy",
                "downloaded_at": saved_meta.get("downloaded_at"),
                "sha256": saved_meta.get("sha256"),
            }
        return None, {"status": "failed", "detail": f"download failed ({error}); no saved copy"}

    meta = {
        "downloaded_at": now().isoformat(),
        "sha256": hashlib.sha256(raw).hexdigest(),  # fingerprint of the exact bytes we downloaded
        "max_count": max(saved_max, len(data["vulnerabilities"])),
    }
    # One single file, so data and fingerprint can never get out of step.
    _write_json_atomic(Path(cache_dir) / "kev" / "kev-saved.json", {**meta, "data": data})
    return data, {"status": "ok", "detail": "downloaded and checked", **meta}


def kev_cve_ids(kev_data):
    if not kev_data:
        return set()
    return {entry["cveID"] for entry in kev_data["vulnerabilities"]}


# ---------------------------------------------------------------- OSV.dev


def _purl_cache_path(cache_dir, purl):
    return Path(cache_dir) / "osv-query" / (hashlib.sha256(purl.encode("utf-8")).hexdigest() + ".json")


def _vuln_cache_path(cache_dir, vuln_id):
    if not VULN_ID_PATTERN.fullmatch(vuln_id):
        raise ValueError("invalid vulnerability id")
    # The "osv-" prefix means the file name can never be a Windows device name like CON or NUL.
    return safe_join(Path(cache_dir) / "osv", "osv-" + vuln_id + ".json")


_MODIFIED_PATTERN = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?Z")


def same_modified_time(a, b):
    """OSV writes the same time with 6 decimals in a batch answer and 9 in a record.

    Compare to 6 decimals so an unchanged record is not downloaded again.
    """
    parts = []
    for value in (a, b):
        match = _MODIFIED_PATTERN.fullmatch(value) if isinstance(value, str) else None
        if not match:
            return False
        parts.append((match.group(1), (match.group(2) or "").ljust(6, "0")[:6]))
    return parts[0] == parts[1]


def _parse_batch_result(result):
    """Return ([(id, modified)], next_page_token) from one OSV batch result, or raise FetchError."""
    if not isinstance(result, dict):
        raise FetchError("OSV result is not an object")
    found = []
    vulns = result.get("vulns", [])
    if vulns is not None and not isinstance(vulns, list):
        raise FetchError("OSV vulns is not a list")
    for item in vulns or []:
        if not isinstance(item, dict):
            raise FetchError("OSV vulnerability entry is not an object")
        vuln_id = item.get("id")
        modified = item.get("modified")
        if not isinstance(vuln_id, str) or not VULN_ID_PATTERN.fullmatch(vuln_id):
            raise FetchError("OSV returned an invalid vulnerability id")
        found.append((vuln_id, modified if isinstance(modified, str) else None))
    token = result.get("next_page_token")
    if token is not None and not isinstance(token, str):
        raise FetchError("OSV page token is not text")
    return found, token


def _query_purls(purls, fetch, sleep):
    """Ask OSV about the purls. Returns {purl: [(id, modified)]} for the ones that got a full answer."""
    answers = {}
    for start in range(0, len(purls), BATCH_SIZE):
        pending = {purl: None for purl in purls[start:start + BATCH_SIZE]}  # purl -> page token
        collected = {purl: {} for purl in pending}
        for _ in range(MAX_PAGE_ROUNDS):
            if not pending:
                break
            order = list(pending)
            queries = []
            for purl in order:
                query = {"package": {"purl": purl}}
                if pending[purl]:
                    query["page_token"] = pending[purl]
                queries.append(query)
            try:
                _, data = _fetch_json(
                    fetch, sleep, OSV_BATCH_URL,
                    json.dumps({"queries": queries}).encode("utf-8"), MAX_OSV_BATCH_BYTES,
                )
                results = data.get("results") if isinstance(data, dict) else None
                if not isinstance(results, list) or len(results) != len(order):
                    raise FetchError("OSV answered with the wrong number of results")
                parsed = [_parse_batch_result(r) for r in results]
            except FetchError:
                break  # everything still pending in this chunk stays unanswered
            next_pending = {}
            for purl, (found, token) in zip(order, parsed):
                collected[purl].update(dict(found))
                if token:
                    next_pending[purl] = token
                else:
                    answers[purl] = sorted(collected[purl].items())
            pending = next_pending
        # anything left in `pending` (or never answered) is simply missing from `answers`
    return answers


def _validate_vuln_record(record, vuln_id):
    if not isinstance(record, dict) or record.get("id") != vuln_id:
        return False
    return isinstance(record.get("affected", []), list)


@dataclass
class Feeds:
    kev: dict | None = None
    kev_ids: set = field(default_factory=set)
    kev_status: dict = field(default_factory=dict)
    osv_status: dict = field(default_factory=dict)
    # purl -> list of vulnerability ids OSV listed, or None when OSV gave no answer
    purl_vulns: dict = field(default_factory=dict)
    # vulnerability id -> OSV record, or None when the details could not be loaded
    vulns: dict = field(default_factory=dict)
    # how many components were NOT sent to OSV (no purl / UNKNOWN), so nothing was checked for them
    unchecked: int = 0
    checked: int = 0

    @property
    def sources_ok(self):
        return self.kev_status.get("status") == "ok" and self.osv_status.get("status") == "ok"

    @property
    def complete(self):
        """True only if every source is ok AND every component was really checked."""
        return self.sources_ok and self.unchecked == 0 and self.checked > 0


def fetch_osv(purls, cache_dir, fetch=http_fetch, sleep=time.sleep, now=utc_now):
    """Ask OSV about every purl. Returns (purl_vulns, vulns, status_dict)."""
    purls = sorted(set(purls))
    problems = []
    used_cache = False

    fresh = _query_purls(purls, fetch, sleep) if purls else {}
    purl_vulns = {}
    listed = {}  # vulnerability id -> modified (from the fresh or cached query)
    for purl in purls:
        cache_path = _purl_cache_path(cache_dir, purl)
        if purl in fresh:
            entries = fresh[purl]
            _write_json_atomic(
                cache_path, {"purl": purl, "vulns": entries, "fetched_at": now().isoformat()}
            )
        else:
            saved = _read_json(cache_path)
            entries = None
            if isinstance(saved, dict) and saved.get("purl") == purl and isinstance(saved.get("vulns"), list):
                try:
                    entries = [(v, m) for v, m in saved["vulns"]]
                    if not all(isinstance(v, str) and VULN_ID_PATTERN.fullmatch(v) for v, _ in entries):
                        entries = None
                except (TypeError, ValueError):
                    entries = None
            if entries is None:
                problems.append("no answer from OSV and no saved answer for one component")
                purl_vulns[purl] = None
                continue
            used_cache = True
            problems.append("OSV did not answer for one component; using an older saved answer")
        purl_vulns[purl] = [v for v, _ in entries]
        for vuln_id, modified in entries:
            listed[vuln_id] = modified

    vulns = {}
    for vuln_id, modified in sorted(listed.items()):
        path = _vuln_cache_path(cache_dir, vuln_id)
        saved = _read_json(path)
        if _validate_vuln_record(saved, vuln_id) and same_modified_time(saved.get("modified"), modified):
            vulns[vuln_id] = saved  # unchanged since we saved it: no download needed
            continue
        try:
            _, record = _fetch_json(fetch, sleep, OSV_VULN_URL + vuln_id, None, MAX_OSV_VULN_BYTES)
            if not _validate_vuln_record(record, vuln_id):
                raise FetchError("OSV record is malformed")
            _write_json_atomic(path, record)
            vulns[vuln_id] = record
        except FetchError:
            if _validate_vuln_record(saved, vuln_id):
                vulns[vuln_id] = saved
                used_cache = True
                problems.append("could not download details of one vulnerability; using an older saved copy")
            else:
                vulns[vuln_id] = None
                problems.append("could not load details of one vulnerability")

    unanswered = any(v is None for v in purl_vulns.values()) or any(v is None for v in vulns.values())
    if unanswered:
        status = "failed"
    elif used_cache:
        status = "stale"
    else:
        status = "ok"
    if status == "ok":
        detail = "all components answered by OSV" if purls else "there was no component to ask about"
    else:
        detail = "; ".join(sorted(set(problems)))
    return purl_vulns, vulns, {"status": status, "detail": detail, "purls_asked": len(purls)}


# ---------------------------------------------------------------- one run


def collect(components, cache_dir, fetch=http_fetch, sleep=time.sleep, now=utc_now):
    """Download everything needed to check `components`. Returns a Feeds object."""
    kev, kev_status = fetch_kev(cache_dir, fetch, sleep, now)
    askable = [c for c in components if c.status == "OK" and c.purl]
    purl_vulns, vulns, osv_status = fetch_osv([c.purl for c in askable], cache_dir, fetch, sleep, now)
    return Feeds(
        kev=kev,
        kev_ids=kev_cve_ids(kev),
        kev_status=kev_status,
        osv_status=osv_status,
        purl_vulns=purl_vulns,
        vulns=vulns,
        checked=len(askable),
        unchecked=len(components) - len(askable),
    )


# ---------------------------------------------------------------- run files


def save_run(run_dir, run, now=utc_now):
    """Save one run as runs/<UTC time>.json. Returns the path."""
    run_dir = Path(run_dir)
    stamp = now().strftime("%Y-%m-%dT%H-%M-%SZ")
    path = run_dir / f"{stamp}.json"
    counter = 1
    while path.exists():
        counter += 1
        path = run_dir / f"{stamp}-{counter:04d}.json"  # zero-padded so the order stays right
    _write_json_atomic(path, run)
    return path


def run_is_complete(run):
    """True if every download source was ok in this run."""
    sources = run.get("sources", {})
    return bool(sources) and all(s.get("status") == "ok" for s in sources.values())


def load_runs(run_dir):
    """Return all readable run files as a list of dicts, oldest first (by their finished_at time)."""
    runs = []
    for path in Path(run_dir).glob("*.json"):
        data = _read_json(path)
        if isinstance(data, dict) and isinstance(data.get("finished_at"), str):
            runs.append((_parse_time(data["finished_at"]), path.stem, data))  # stem: "...Z" sorts before "...Z-0002"
    # Runs whose time cannot be read sort first and are never used as "the latest".
    epoch = datetime.min.replace(tzinfo=timezone.utc)
    runs.sort(key=lambda item: (item[0] or epoch, item[1]))
    return [data for _, _, data in runs]


def status_report(run_dir, now=utc_now):
    """Return the text lines for `cra status`, with loud warnings."""
    runs = load_runs(run_dir)
    if not runs:
        return ["WARNING: no run found yet. Nothing has been checked. Run `cra run` first."]
    lines = []
    current = now()
    last = runs[-1]
    good = [r for r in runs if run_is_complete(r) and _parse_time(r["finished_at"]) is not None]
    if not good:
        lines.append("WARNING: there has never been a fully successful run.")
    else:
        finished = _parse_time(good[-1]["finished_at"])
        age = current - finished
        if age < timedelta(0):
            lines.append(
                f"WARNING: the last successful run is dated in the future ({good[-1]['finished_at']}). "
                "Is the computer clock wrong? Do not rely on the age."
            )
        else:
            lines.append(f"Last successful run: {good[-1]['finished_at']} ({int(age.total_seconds() // 3600)} hours ago)")
            if age > timedelta(hours=STALE_AFTER_HOURS):
                lines.append(
                    f"WARNING: the last successful run was more than {STALE_AFTER_HOURS} hours ago. "
                    "Is the scheduler still running? New exploited vulnerabilities may be missing."
                )
    if run_is_complete(last) and _parse_time(last["finished_at"]) is not None:
        lines.append("Latest run: all sources ok.")
    else:
        lines.append("WARNING: RESULT INCOMPLETE - the latest run was not fully successful. Do not rely on it.")
        for name, source in sorted(last.get("sources", {}).items()):
            if source.get("status") != "ok":
                lines.append(f"  {name}: {source.get('status')} - {source.get('detail')}")
    unchecked = (last.get("components") or {}).get("unchecked")
    if isinstance(unchecked, int) and unchecked > 0:
        lines.append(f"WARNING: {unchecked} component(s) could NOT be checked in the latest run (UNKNOWN). A human must look.")
    return lines
