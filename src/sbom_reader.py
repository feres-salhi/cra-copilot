"""Part 1: read a CycloneDX SBOM and list its components.

Rule: when we are not sure about a component, it becomes UNKNOWN.
It is never treated as "safe".
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path

from packageurl import PackageURL

SUPPORTED_ECOSYSTEMS = {"pypi", "maven"}


class SbomError(Exception):
    """The whole SBOM file is rejected."""


@dataclass
class Component:
    name: str | None
    version: str | None
    purl: str | None
    ecosystem: str | None
    status: str  # "OK" or "UNKNOWN"
    reason: str | None = None  # only set when status is "UNKNOWN"


def _text(value):
    """Return value if it is a non-empty string, otherwise None."""
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _same_name(ecosystem, name_a, name_b):
    """PyPI treats Requests, requests and re_quests-style names as the same."""
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name_a).lower() == re.sub(r"[-_.]+", "-", name_b).lower()
    return name_a == name_b


def _read_component(raw):
    name = _text(raw.get("name"))
    version = _text(raw.get("version"))
    purl = _text(raw.get("purl"))

    def unknown(reason, ecosystem=None):
        return Component(name, version, purl, ecosystem, "UNKNOWN", reason)

    if purl is None:
        return unknown("no purl")
    if version is None:
        return unknown("no version")
    if name is None:
        return unknown("no name")

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
    if ecosystem == "maven" and not parsed.namespace:
        return unknown("maven purl has no namespace", ecosystem)
    if not _same_name(ecosystem, parsed.name, name):
        return unknown("purl name does not match name", ecosystem)
    if parsed.version != version:
        return unknown("purl version does not match version", ecosystem)

    return Component(name, version, purl, ecosystem, "OK")


def read_sbom(path):
    """Read a CycloneDX JSON file and return a list of Component objects."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as error:  # ValueError covers bad JSON/UTF-8
        raise SbomError(f"cannot read SBOM file: {error}") from error

    if not isinstance(data, dict):
        raise SbomError("SBOM must be a JSON object")
    if data.get("bomFormat") != "CycloneDX":
        raise SbomError('bomFormat must be "CycloneDX"')

    # Components can contain components (nested). Walk them all, without recursion.
    components = []
    to_visit = [data.get("components", [])]
    while to_visit:
        raw_list = to_visit.pop(0)
        if not isinstance(raw_list, list):
            raise SbomError('"components" must be a list')
        for item in raw_list:
            if not isinstance(item, dict):
                raise SbomError("every component must be a JSON object")
            components.append(_read_component(item))
            if "components" in item:
                to_visit.append(item["components"])

    return components
