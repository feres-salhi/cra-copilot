import json
from pathlib import Path

import pytest

from src.sbom_reader import SbomError, read_sbom

DEMO_SBOM = Path(__file__).parent.parent / "demo-data" / "demo-thermostat-sbom.json"


def test_finds_five_components():
    assert len(read_sbom(DEMO_SBOM)) == 5


def test_both_log4j_versions_are_ok():
    log4j = [c for c in read_sbom(DEMO_SBOM) if c.name == "log4j-core"]
    assert sorted(c.version for c in log4j) == ["2.14.1", "2.17.1"]
    assert all(c.status == "OK" and c.ecosystem == "maven" for c in log4j)


def test_pypi_components_are_ok():
    by_name = {c.name: c for c in read_sbom(DEMO_SBOM)}
    for name in ("requests", "packaging"):
        assert by_name[name].status == "OK"
        assert by_name[name].ecosystem == "pypi"


def test_component_without_purl_is_unknown():
    by_name = {c.name: c for c in read_sbom(DEMO_SBOM)}
    firmware = by_name["smartheat-firmware-core"]
    assert firmware.status == "UNKNOWN"
    assert firmware.reason == "no purl"


def _write_sbom(tmp_path, data):
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _one_component(tmp_path, component):
    path = _write_sbom(
        tmp_path, {"bomFormat": "CycloneDX", "components": [component]}
    )
    return read_sbom(path)[0]


def test_wrong_bom_format_is_rejected(tmp_path):
    path = _write_sbom(tmp_path, {"bomFormat": "SPDX", "components": []})
    with pytest.raises(SbomError):
        read_sbom(path)


def test_missing_bom_format_is_rejected(tmp_path):
    with pytest.raises(SbomError):
        read_sbom(_write_sbom(tmp_path, {"components": []}))


def test_broken_json_is_rejected(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(SbomError):
        read_sbom(path)


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(SbomError):
        read_sbom(tmp_path / "does-not-exist.json")


def test_component_without_version_is_unknown(tmp_path):
    c = _one_component(tmp_path, {"name": "requests", "purl": "pkg:pypi/requests"})
    assert (c.status, c.reason) == ("UNKNOWN", "no version")


def test_unsupported_ecosystem_is_unknown(tmp_path):
    c = _one_component(
        tmp_path,
        {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
    )
    assert c.status == "UNKNOWN"
    assert c.ecosystem == "npm"
    assert "unsupported ecosystem" in c.reason


def test_unparsable_purl_is_unknown(tmp_path):
    c = _one_component(
        tmp_path, {"name": "x", "version": "1.0", "purl": "this is not a purl"}
    )
    assert c.status == "UNKNOWN"


def test_non_text_version_is_unknown(tmp_path):
    c = _one_component(
        tmp_path, {"name": "x", "version": 2, "purl": "pkg:pypi/x@2"}
    )
    assert (c.status, c.reason) == ("UNKNOWN", "no version")


def test_nested_components_are_found(tmp_path):
    path = _write_sbom(
        tmp_path,
        {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "name": "outer",
                    "version": "1.0",
                    "purl": "pkg:pypi/outer@1.0",
                    "components": [
                        {
                            "name": "log4j-core",
                            "version": "2.14.1",
                            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                        }
                    ],
                }
            ],
        },
    )
    found = read_sbom(path)
    assert [c.name for c in found] == ["outer", "log4j-core"]
    assert all(c.status == "OK" for c in found)


def test_purl_version_must_match_version_field(tmp_path):
    c = _one_component(
        tmp_path, {"name": "requests", "version": "2.17.1", "purl": "pkg:pypi/requests@2.14.1"}
    )
    assert (c.status, c.reason) == ("UNKNOWN", "purl version does not match version")


def test_purl_name_must_match_name_field(tmp_path):
    c = _one_component(
        tmp_path, {"name": "requests", "version": "1.0", "purl": "pkg:pypi/evil@1.0"}
    )
    assert (c.status, c.reason) == ("UNKNOWN", "purl name does not match name")


def test_pypi_name_spelling_differences_are_allowed(tmp_path):
    c = _one_component(
        tmp_path, {"name": "Typing_Extensions", "version": "4.0", "purl": "pkg:pypi/typing-extensions@4.0"}
    )
    assert c.status == "OK"


def test_purl_without_version_is_unknown(tmp_path):
    c = _one_component(tmp_path, {"name": "x", "version": "1.0", "purl": "pkg:pypi/x"})
    assert c.status == "UNKNOWN"


def test_maven_purl_without_namespace_is_unknown(tmp_path):
    c = _one_component(tmp_path, {"name": "x", "version": "1", "purl": "pkg:maven/x@1"})
    assert (c.status, c.reason) == ("UNKNOWN", "maven purl has no namespace")


def test_component_without_name_is_unknown(tmp_path):
    c = _one_component(tmp_path, {"version": "1", "purl": "pkg:pypi/x@1"})
    assert (c.status, c.reason) == ("UNKNOWN", "no name")


def test_version_with_spaces_is_trimmed(tmp_path):
    c = _one_component(
        tmp_path, {"name": "x", "version": " 1.0 ", "purl": "pkg:pypi/x@1.0"}
    )
    assert (c.status, c.version) == ("OK", "1.0")


def test_file_with_byte_order_mark_is_read(tmp_path):
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + b'{"bomFormat": "CycloneDX", "components": []}')
    assert read_sbom(path) == []
