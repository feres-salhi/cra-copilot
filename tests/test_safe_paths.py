import os

import pytest

from src.safe_paths import safe_join


def test_a_plain_name_is_joined(tmp_path):
    assert safe_join(tmp_path, "osv-GHSA-1.json") == tmp_path.resolve() / "osv-GHSA-1.json"


@pytest.mark.parametrize(
    "name",
    [
        "..",
        "../x",
        "..\\x",
        "a/b",
        "a\\b",
        "/etc/passwd",
        "C:\\Windows\\x",
        "C:x",
        "\\\\server\\share\\x",
        "a..b",
        "",
        ".hidden",
        "x" * 200,
        "a b",
        "a\nb",
        "a\x00b",
        "a:stream",
        None,
        5,
    ],
)
def test_unsafe_names_are_refused(tmp_path, name):
    with pytest.raises(ValueError):
        safe_join(tmp_path, name)


def test_a_symlink_that_points_outside_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    inside = tmp_path / "inside"
    inside.mkdir()
    link = inside / "link.json"
    try:
        os.symlink(outside / "target.json", link)
    except (OSError, NotImplementedError):
        pytest.skip("this computer does not allow creating symlinks")
    with pytest.raises(ValueError, match="leaves its folder"):
        safe_join(inside, "link.json")


@pytest.mark.parametrize("name", ["CON", "con.json", "NUL.txt", "COM1", "lpt9.json", "AUX.x.y", "a.", "a.json."])
def test_windows_device_names_and_trailing_dots_are_refused(tmp_path, name):
    with pytest.raises(ValueError):
        safe_join(tmp_path, name)


def test_names_that_only_contain_a_device_name_are_fine(tmp_path):
    assert safe_join(tmp_path, "osv-CON.json").name == "osv-CON.json"
    assert safe_join(tmp_path, "CONTENT.json").name == "CONTENT.json"
