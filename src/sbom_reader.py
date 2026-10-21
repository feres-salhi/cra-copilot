"""Part 1: read a CycloneDX SBOM and list its components.

Rule: when we are not sure about a component, it becomes UNKNOWN.
It is never treated as "safe".

The SBOM file is treated as possibly hostile:
- a file that is too big, too deep, has too many components or has
  duplicate JSON keys is rejected as a whole;
- a component with a strange name, version or purl becomes UNKNOWN
  (only that component), and the strange text is not kept.
"""

import json
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from packageurl import PackageURL

SUPPORTED_ECOSYSTEMS = {"pypi", "maven"}

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_DEPTH = 32
MAX_COMPONENTS = 5000
MAX_CONFIG_BYTES = 64 * 1024
MAX_TEXT_LENGTH = 256

# Strict allowed characters (plain ASCII only, no spaces, no control characters).
NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:@/~-]*")
VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~!-]*")
# No % and no # in a purl (no hidden escapes, no subpath). A "?key=value&key=value" part is allowed
# by this pattern, but later only the harmless qualifiers in HARMLESS_QUALIFIERS are accepted.
PURL_PATTERN = re.compile(r"pkg:[A-Za-z0-9._+~:/@!-]+(\?[A-Za-z0-9._=&-]+)?")
# Real SBOM tools often write pkg:maven/...@1.0?type=jar. These two do not change WHICH package it is.
HARMLESS_QUALIFIERS = {"type", "classifier"}
QUALIFIER_VALUE_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,32}")
# Each part of a Maven group id (the purl "namespace"), e.g. org / apache / logging.
GROUP_SEGMENT_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
PRODUCT_NAME_PATTERN = re.compile(r"[A-Za-zÄÖÜäöüß0-9][A-Za-zÄÖÜäöüß0-9 ._,&()+-]*")

EU_MEMBER_STATES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE",
    "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
}


class SbomError(Exception):
    """The whole SBOM file is rejected."""


class ConfigError(Exception):
    """The product config file is rejected."""


@dataclass
class Component:
    name: str | None
    version: str | None
    purl: str | None
    ecosystem: str | None
    status: str  # "OK" or "UNKNOWN"
    reason: str | None = None  # only set when status is "UNKNOWN"


@dataclass
class SbomResult:
    components: list
    warnings: list = field(default_factory=list)


def _clean(value, pattern):
    """Return (text, problem). problem is None, "missing" or "invalid".

    Only plain spaces around the text are trimmed. Anything else odd
    (line breaks, control characters, non-ASCII, too long) is "invalid".
    """
    if value is None:
        return None, "missing"
    if not isinstance(value, str):
        return None, "invalid"
    text = value.strip(" ")
    if not text:
        return None, "missing"
    if len(text) > MAX_TEXT_LENGTH or not pattern.fullmatch(text):
        return None, "invalid"
    return text, None


def _same_name(ecosystem, name_a, name_b):
    """PyPI treats Requests, requests and typing_extensions/typing-extensions as the same."""
    if ecosystem == "pypi":
        normalize = lambda n: re.sub(r"[-_.]+", "-", n).lower()
        return normalize(name_a) == normalize(name_b)
    return name_a == name_b


def _read_component(raw):
    purl, purl_problem = _clean(raw.get("purl"), PURL_PATTERN)
    version, version_problem = _clean(raw.get("version"), VERSION_PATTERN)
    name, name_problem = _clean(raw.get("name"), NAME_PATTERN)

    def unknown(reason, ecosystem=None):
        return Component(name, version, purl, ecosystem, "UNKNOWN", reason)

    if purl_problem == "missing":
        return unknown("no purl")
    if purl_problem:
        return unknown("invalid purl")
    if version_problem == "missing":
        return unknown("no version")
    if version_problem:
        return unknown("invalid version")
    if name_problem == "missing":
        return unknown("no name")
    if name_problem:
        return unknown("invalid name")

    try:
        parsed = PackageURL.from_string(purl)
    except ValueError:
        return unknown("purl cannot be parsed")

    ecosystem = parsed.type
    if ecosystem not in SUPPORTED_ECOSYSTEMS:
        return unknown(f"unsupported ecosystem: {ecosystem}", ecosystem)

    # The purl is the identity the matcher will use, so it must agree with the fields.
    if not parsed.name or not parsed.version:
        return unknown("purl has no name or version", ecosystem)
    # The library quietly tidies the qualifier text (keeps the last duplicate, drops empty keys),
    # so look at the raw text ourselves.
    if "?" in purl:
        keys = [pair.partition("=")[0] for pair in purl.split("?", 1)[1].split("&")]
        if "" in keys or len(keys) != len(set(keys)):
            return unknown("purl has qualifiers that are not supported", ecosystem)
    qualifiers = parsed.qualifiers or {}
    if (set(qualifiers) - HARMLESS_QUALIFIERS) or not all(
        QUALIFIER_VALUE_PATTERN.fullmatch(str(v)) for v in qualifiers.values()
    ):
        return unknown("purl has qualifiers that are not supported", ecosystem)
    if ecosystem == "maven" and not parsed.namespace:
        return unknown("maven purl has no namespace", ecosystem)
    if ecosystem == "pypi" and parsed.namespace:
        return unknown("pypi purl must not have a namespace", ecosystem)
    if ecosystem == "maven":
        segments = parsed.namespace.split("/")
        if not all(GROUP_SEGMENT_PATTERN.fullmatch(s) and ".." not in s for s in segments):
            return unknown("maven purl namespace has invalid characters", ecosystem)
        group, group_problem = _clean(raw.get("group"), NAME_PATTERN)
        if group_problem == "invalid" or (group is not None and group != parsed.namespace.replace("/", ".")):
            return unknown("purl namespace does not match group", ecosystem)
    if not _same_name(ecosystem, parsed.name, name):
        return unknown("purl name does not match name", ecosystem)
    if parsed.version != version:
        return unknown("purl version does not match version", ecosystem)

    # Keep a canonical purl rebuilt from its parts (no qualifiers), never the raw text.
    canonical = PackageURL(parsed.type, parsed.namespace, parsed.name, parsed.version).to_string()
    return Component(name, version, canonical, ecosystem, "OK")


def _read_limited(path, limit):
    """Read at most limit + 1 bytes of a regular file (so a huge file is never fully loaded)."""
    file_path = Path(path)
    if not file_path.is_file():
        raise OSError("not a regular file")
    with open(file_path, "rb") as handle:
        return handle.read(limit + 1)


def _reject_constant(name):
    raise SbomError(f"JSON contains {name}, which is not allowed")


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SbomError("duplicate key in JSON object")
        result[key] = value
    return result


def _check_depth(text):
    """Reject text whose [] / {} nesting is deeper than MAX_DEPTH.

    This runs BEFORE json.loads, so a very deep file cannot crash the parser.
    Brackets inside quoted strings are ignored.
    """
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise SbomError(f"JSON is nested deeper than {MAX_DEPTH} levels")
        elif char in "]}":
            depth -= 1


def _load_json(path):
    try:
        raw_bytes = _read_limited(path, MAX_FILE_BYTES)
        if len(raw_bytes) > MAX_FILE_BYTES:
            raise SbomError(f"SBOM file is larger than {MAX_FILE_BYTES} bytes")
        text = raw_bytes.decode("utf-8-sig")
    except (OSError, ValueError, TypeError) as error:
        raise SbomError(f"cannot read SBOM file: {error}") from error

    _check_depth(text)
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except RecursionError as error:
        raise SbomError("JSON is nested too deeply") from error
    except ValueError as error:
        raise SbomError(f"SBOM is not valid JSON: {error}") from error


def load_sbom(path):
    """Read a CycloneDX JSON file. Returns an SbomResult (components + warnings)."""
    data = _load_json(path)

    if not isinstance(data, dict):
        raise SbomError("SBOM must be a JSON object")
    if data.get("bomFormat") != "CycloneDX":
        raise SbomError('bomFormat must be "CycloneDX"')

    # Components can contain components (nested). Walk them all, without recursion.
    components = []
    to_visit = deque([data.get("components", [])])
    while to_visit:
        raw_list = to_visit.popleft()
        if not isinstance(raw_list, list):
            raise SbomError('"components" must be a list')
        for item in raw_list:
            if not isinstance(item, dict):
                raise SbomError("every component must be a JSON object")
            if len(components) >= MAX_COMPONENTS:
                raise SbomError(f"SBOM has more than {MAX_COMPONENTS} components")
            components.append(_read_component(item))
            if "components" in item:
                to_visit.append(item["components"])

    warnings = []
    if not components:
        warnings.append("SBOM has no components: nothing could be checked")
    if not data.get("dependencies"):
        warnings.append("SBOM has no dependency list: the tool cannot see every component")
    return SbomResult(components, warnings)


def read_sbom(path):
    """Read a CycloneDX JSON file and return only the list of Component objects."""
    return load_sbom(path).components


def read_product_config(path):
    """Read the product config. Returns a dict with product_name, manufacturer, member_states."""
    try:
        raw_bytes = _read_limited(path, MAX_CONFIG_BYTES)
        if len(raw_bytes) > MAX_CONFIG_BYTES:
            raise ConfigError("config file is too large")
        text = raw_bytes.decode("utf-8-sig")
        _check_depth(text)
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except SbomError as error:  # duplicate keys, too deep, NaN
        raise ConfigError(str(error)) from error
    except (OSError, ValueError, TypeError, RecursionError) as error:
        raise ConfigError(f"cannot read config file: {error}") from error

    if not isinstance(data, dict):
        raise ConfigError("config must be a JSON object")

    product_name, problem = _clean(data.get("product_name"), PRODUCT_NAME_PATTERN)
    if problem:
        raise ConfigError("product_name is missing or has invalid characters")
    manufacturer, problem = _clean(data.get("manufacturer"), PRODUCT_NAME_PATTERN)
    if problem:
        raise ConfigError("manufacturer is missing or has invalid characters")

    states = data.get("member_states")
    if not isinstance(states, list) or not all(isinstance(s, str) for s in states):
        raise ConfigError("member_states must be a list of two-letter country codes")
    if not states:
        raise ConfigError("member_states is empty: at least one EU country is needed")
    if any(s not in EU_MEMBER_STATES for s in states):
        raise ConfigError("member_states contains a code that is not an EU member state")
    if len(set(states)) != len(states):
        raise ConfigError("member_states contains a duplicate")

    return {"product_name": product_name, "manufacturer": manufacturer, "member_states": states}
