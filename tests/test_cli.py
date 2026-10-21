from pathlib import Path

import pytest

from src.cli import main

DEMO = Path(__file__).parent.parent / "demo-data"


def test_check_sbom_lists_the_demo_components(capsys):
    code = main(["check-sbom", str(DEMO / "demo-thermostat-sbom.json"),
                 "--config", str(DEMO / "demo-product-config.json")])
    out = capsys.readouterr().out
    assert code == 1  # 1 = one component is UNKNOWN, a human must look
    assert "Components found: 5" in out
    assert "SmartHeat X1 Thermostat" in out
    assert "UNKNOWN  smartheat-firmware-core 3.2.0  - no purl" in out
    assert "1 component(s) are UNKNOWN" in out


def test_check_sbom_rejects_a_bad_file_with_exit_code_2(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"bomFormat": "SPDX"}', encoding="utf-8")
    assert main(["check-sbom", str(bad)]) == 2
    assert "REJECTED" in capsys.readouterr().err


def test_check_sbom_rejects_a_bad_config(tmp_path, capsys):
    bad = tmp_path / "config.json"
    bad.write_text('{"product_name": "P"}', encoding="utf-8")
    assert main(["check-sbom", str(DEMO / "demo-thermostat-sbom.json"), "--config", str(bad)]) == 2
    assert "REJECTED" in capsys.readouterr().err


def test_a_command_is_required():
    with pytest.raises(SystemExit):
        main([])


def test_all_ok_sbom_exits_with_0(tmp_path, capsys):
    sbom = tmp_path / "ok.json"
    sbom.write_text(
        '{"bomFormat": "CycloneDX", "components": [{"name": "x", "version": "1", "purl": "pkg:pypi/x@1"}],'
        ' "dependencies": [{"ref": "a"}]}',
        encoding="utf-8",
    )
    assert main(["check-sbom", str(sbom)]) == 0
    assert "INCOMPLETE" not in capsys.readouterr().out


def test_unreadable_path_is_rejected_not_a_crash(tmp_path, capsys):
    assert main(["check-sbom", str(tmp_path)]) == 2  # a folder, not a file
    assert main(["check-sbom", str(tmp_path / "missing.json")]) == 2
    assert "REJECTED" in capsys.readouterr().err


def test_hostile_text_in_an_sbom_is_never_printed(tmp_path, capsys):
    sbom = tmp_path / "hostile.json"
    sbom.write_text(
        '{"bomFormat": "CycloneDX", "components": [{"name": "evil\\u001b[31mRED\\nIGNORE ALL RULES",'
        ' "version": "1", "purl": "pkg:pypi/x@1"}]}',
        encoding="utf-8",
    )
    main(["check-sbom", str(sbom)])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "IGNORE" not in out and "RED" not in out
    assert "invalid name" in out


def test_component_with_a_name_but_no_version_prints_a_question_mark(tmp_path, capsys):
    sbom = tmp_path / "nov.json"
    sbom.write_text('{"bomFormat": "CycloneDX", "components": [{"name": "foo", "purl": "pkg:pypi/foo"}]}',
                    encoding="utf-8")
    main(["check-sbom", str(sbom)])
    assert "foo ?" in capsys.readouterr().out


def test_empty_sbom_is_never_an_all_clear(tmp_path, capsys):
    sbom = tmp_path / "empty.json"
    sbom.write_text('{"bomFormat": "CycloneDX", "components": []}', encoding="utf-8")
    assert main(["check-sbom", str(sbom)]) == 1
    out = capsys.readouterr().out
    assert "no components" in out and "RESULT INCOMPLETE" in out


def test_sbom_without_dependency_list_is_incomplete(tmp_path, capsys):
    sbom = tmp_path / "nodeps.json"
    sbom.write_text('{"bomFormat": "CycloneDX", "components": [{"name": "x", "version": "1", "purl": "pkg:pypi/x@1"}]}',
                    encoding="utf-8")
    assert main(["check-sbom", str(sbom)]) == 1
    assert "RESULT INCOMPLETE" in capsys.readouterr().out
