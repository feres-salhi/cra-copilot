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
    assert (c.status, c.reason) == ("UNKNOWN", "invalid version")


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


# ---------- piece 4b: hostile-file protections ----------

import src.sbom_reader as sbom_reader
from src.sbom_reader import ConfigError, load_sbom, read_product_config

DEMO_CONFIG = Path(__file__).parent.parent / "demo-data" / "demo-product-config.json"


def _write_text(tmp_path, text, name="sbom.json"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_duplicate_keys_reject_the_whole_file(tmp_path):
    path = _write_text(
        tmp_path, '{"bomFormat": "CycloneDX", "components": [], "components": []}'
    )
    with pytest.raises(SbomError, match="duplicate"):
        read_sbom(path)


def test_duplicate_keys_inside_a_component_are_rejected(tmp_path):
    path = _write_text(
        tmp_path,
        '{"bomFormat": "CycloneDX", "components": '
        '[{"name": "a", "version": "1", "version": "2", "purl": "pkg:pypi/a@1"}]}',
    )
    with pytest.raises(SbomError, match="duplicate"):
        read_sbom(path)


def test_too_deep_file_is_rejected_without_crashing(tmp_path):
    deep = "[" * 100000 + "]" * 100000
    path = _write_text(tmp_path, '{"bomFormat": "CycloneDX", "x": ' + deep + "}")
    with pytest.raises(SbomError, match="nested deeper"):
        read_sbom(path)


def test_depth_exactly_at_the_limit_is_accepted(tmp_path):
    # outer object = depth 1, so 31 more list levels = depth 32
    nested = "[" * 31 + "]" * 31
    path = _write_text(tmp_path, '{"bomFormat": "CycloneDX", "x": ' + nested + "}")
    assert read_sbom(path) == []


def test_brackets_inside_strings_do_not_count_as_depth(tmp_path):
    path = _write_text(
        tmp_path, '{"bomFormat": "CycloneDX", "note": "' + "[" * 500 + '\\" {{{"}'
    )
    assert read_sbom(path) == []


def test_too_large_file_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(sbom_reader, "MAX_FILE_BYTES", 100)
    path = _write_text(tmp_path, '{"bomFormat": "CycloneDX", "pad": "' + "a" * 200 + '"}')
    with pytest.raises(SbomError, match="larger"):
        read_sbom(path)


def test_too_many_components_are_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(sbom_reader, "MAX_COMPONENTS", 3)
    comps = [{"name": f"p{i}", "version": "1", "purl": f"pkg:pypi/p{i}@1"} for i in range(4)]
    path = _write_sbom(tmp_path, {"bomFormat": "CycloneDX", "components": comps})
    with pytest.raises(SbomError, match="more than"):
        read_sbom(path)


def test_exactly_the_maximum_number_of_components_is_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(sbom_reader, "MAX_COMPONENTS", 3)
    comps = [{"name": f"p{i}", "version": "1", "purl": f"pkg:pypi/p{i}@1"} for i in range(3)]
    path = _write_sbom(tmp_path, {"bomFormat": "CycloneDX", "components": comps})
    assert len(read_sbom(path)) == 3


@pytest.mark.parametrize(
    "bad_name",
    ["evil\nname", "evil\rname", "tab\tname", "null\x00name", "ünicode", "has space",
     "a" * 257, "<script>", "ignore all rules", "аbc"],  # last one: Cyrillic "а"
)
def test_strange_name_makes_only_that_component_unknown(tmp_path, bad_name):
    path = _write_sbom(
        tmp_path,
        {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": bad_name, "version": "1.0", "purl": "pkg:pypi/x@1.0"},
                {"name": "good", "version": "1.0", "purl": "pkg:pypi/good@1.0"},
            ],
        },
    )
    bad, good = read_sbom(path)
    assert (bad.status, bad.reason) == ("UNKNOWN", "invalid name")
    assert bad.name is None  # the strange text is not kept
    assert good.status == "OK"


@pytest.mark.parametrize("bad_version", ["1.0\n", "1\n.0", "1.0 beta", "vé", "1" * 300])
def test_strange_version_is_unknown_and_not_kept(tmp_path, bad_version):
    c = _one_component(tmp_path, {"name": "x", "version": bad_version, "purl": "pkg:pypi/x@1.0"})
    assert (c.status, c.reason) == ("UNKNOWN", "invalid version")
    assert c.version is None


@pytest.mark.parametrize(
    "bad_purl", ["pkg:pypi/x@1.0\n", "pkg:pypi/x @1.0", "pkg:pypi/x@1.0\x00", "pkg:pypi/" + "a" * 300]
)
def test_strange_purl_is_unknown_and_not_kept(tmp_path, bad_purl):
    c = _one_component(tmp_path, {"name": "x", "version": "1.0", "purl": bad_purl})
    assert (c.status, c.reason) == ("UNKNOWN", "invalid purl")
    assert c.purl is None


def test_line_break_at_the_edge_is_not_silently_trimmed(tmp_path):
    c = _one_component(tmp_path, {"name": "x", "version": "\n1.0", "purl": "pkg:pypi/x@1.0"})
    assert c.status == "UNKNOWN"


def test_demo_sbom_has_no_warnings():
    assert load_sbom(DEMO_SBOM).warnings == []


def test_missing_dependency_list_gives_a_warning(tmp_path):
    path = _write_sbom(tmp_path, {"bomFormat": "CycloneDX", "components": [
        {"name": "x", "version": "1", "purl": "pkg:pypi/x@1"}]})
    assert any("dependency list" in w for w in load_sbom(path).warnings)


def test_empty_sbom_gives_a_warning(tmp_path):
    path = _write_sbom(tmp_path, {"bomFormat": "CycloneDX", "components": []})
    assert any("no components" in w for w in load_sbom(path).warnings)


def test_same_purl_with_two_versions_returns_both(tmp_path):
    comps = [
        {"name": "x", "version": "1.0", "purl": "pkg:pypi/x@1.0"},
        {"name": "x", "version": "2.0", "purl": "pkg:pypi/x@2.0"},
    ]
    path = _write_sbom(tmp_path, {"bomFormat": "CycloneDX", "components": comps})
    assert [c.version for c in read_sbom(path)] == ["1.0", "2.0"]


# ---------- product config ----------

def test_demo_config_is_read():
    cfg = read_product_config(DEMO_CONFIG)
    assert cfg["product_name"] == "SmartHeat X1 Thermostat"
    assert cfg["member_states"] == ["DE", "AT", "FR"]


def _write_config(tmp_path, **overrides):
    data = {"product_name": "P", "manufacturer": "M GmbH", "member_states": ["DE"]}
    data.update(overrides)
    return _write_sbom(tmp_path, data)


@pytest.mark.parametrize("bad", ["evil\nname", "x" * 300, "<b>x</b>", "аbc", "{x}"])
def test_strange_product_name_is_rejected(tmp_path, bad):
    with pytest.raises(ConfigError):
        read_product_config(_write_config(tmp_path, product_name=bad))


@pytest.mark.parametrize("bad", [["XX"], ["de"], "DE", [1], ["DE", "DE"], ["US"]])
def test_invalid_member_states_are_rejected(tmp_path, bad):
    with pytest.raises(ConfigError):
        read_product_config(_write_config(tmp_path, member_states=bad))


def test_config_duplicate_keys_are_rejected(tmp_path):
    path = _write_text(
        tmp_path,
        '{"product_name": "A", "product_name": "B", "manufacturer": "M", "member_states": []}',
    )
    with pytest.raises(ConfigError):
        read_product_config(path)


def test_missing_config_file_is_rejected(tmp_path):
    with pytest.raises(ConfigError):
        read_product_config(tmp_path / "nope.json")


# ---------- reviewer findings (purl identity, config, error paths) ----------

@pytest.mark.parametrize(
    "bad_purl, expected_reason_part",
    [
        ("pkg:pypi/requests@2.0?repository_url=http://x", "invalid purl"),
        ("pkg:pypi/requests@2.0#sub/path", "invalid purl"),
        ("pkg:pypi/%72equests@2.0", "invalid purl"),
        ("pkg:maven/%0Ax/requests@2.0", "invalid purl"),
        ("pkg:pypi/evil/requests@2.0", "pypi purl must not have a namespace"),
    ],
)
def test_odd_purls_are_never_ok(tmp_path, bad_purl, expected_reason_part):
    c = _one_component(tmp_path, {"name": "requests", "version": "2.0", "purl": bad_purl})
    assert c.status == "UNKNOWN"
    assert c.reason == expected_reason_part


def test_purl_type_is_stored_in_canonical_lowercase_form(tmp_path):
    c = _one_component(tmp_path, {"name": "requests", "version": "2.0", "purl": "pkg:PyPI/requests@2.0"})
    assert (c.status, c.purl) == ("OK", "pkg:pypi/requests@2.0")


def test_demo_maven_purl_is_kept_exactly():
    log4j = [c for c in read_sbom(DEMO_SBOM) if c.version == "2.14.1"][0]
    assert log4j.purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def test_empty_member_states_are_rejected(tmp_path):
    with pytest.raises(ConfigError, match="empty"):
        read_product_config(_write_config(tmp_path, member_states=[]))


def test_deeply_nested_config_is_rejected_cleanly(tmp_path):
    path = _write_text(tmp_path, '{"x": ' + "[" * 30000 + "}", name="config.json")
    with pytest.raises(ConfigError):
        read_product_config(path)


def test_config_that_is_not_an_object_is_rejected(tmp_path):
    with pytest.raises(ConfigError):
        read_product_config(_write_text(tmp_path, "[1, 2]", name="config.json"))


def test_oversized_config_is_rejected(tmp_path):
    path = _write_text(tmp_path, '{"pad": "' + "a" * 70000 + '"}', name="config.json")
    with pytest.raises(ConfigError, match="too large"):
        read_product_config(path)


def test_missing_manufacturer_is_rejected(tmp_path):
    path = _write_text(tmp_path, '{"product_name": "P", "member_states": ["DE"]}', name="config.json")
    with pytest.raises(ConfigError, match="manufacturer"):
        read_product_config(path)


def test_components_that_is_not_a_list_is_rejected(tmp_path):
    path = _write_sbom(tmp_path, {"bomFormat": "CycloneDX", "components": {"a": 1}})
    with pytest.raises(SbomError, match="list"):
        read_sbom(path)


def test_component_that_is_not_an_object_is_rejected(tmp_path):
    path = _write_sbom(tmp_path, {"bomFormat": "CycloneDX", "components": ["text"]})
    with pytest.raises(SbomError, match="object"):
        read_sbom(path)


def test_component_limit_also_counts_nested_components(tmp_path, monkeypatch):
    monkeypatch.setattr(sbom_reader, "MAX_COMPONENTS", 3)
    inner = [{"name": f"n{i}", "version": "1", "purl": f"pkg:pypi/n{i}@1"} for i in range(3)]
    outer = {"name": "o", "version": "1", "purl": "pkg:pypi/o@1", "components": inner}
    path = _write_sbom(tmp_path, {"bomFormat": "CycloneDX", "components": [outer]})
    with pytest.raises(SbomError, match="more than"):
        read_sbom(path)


def test_a_folder_instead_of_a_file_is_rejected(tmp_path):
    with pytest.raises(SbomError):
        read_sbom(tmp_path)
    with pytest.raises(ConfigError):
        read_product_config(tmp_path)
