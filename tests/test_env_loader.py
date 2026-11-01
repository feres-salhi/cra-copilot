"""Phase 3, piece 5: the tiny .env loader (no new package). It only READS a file; it never prints a value."""

import os

import pytest

from src import env_loader as el


def write_env(tmp_path, text):
    path = tmp_path / "test.env"
    path.write_text(text, encoding="utf-8")
    return path


def test_simple_lines_comments_quotes_and_spaces(tmp_path):
    path = write_env(tmp_path, "# a comment\n\nGEMINI_MODEL=gemini-test\n  FOO = bar baz  \nQUOTED=\"hello world\"\nSINGLE='x y'\nEMPTY=\n")
    assert el.load_env_file(path) == {"GEMINI_MODEL": "gemini-test", "FOO": "bar baz", "QUOTED": "hello world",
                                      "SINGLE": "x y", "EMPTY": ""}


def test_windows_line_endings_work(tmp_path):
    path = tmp_path / "win.env"
    path.write_bytes(b"A=1\r\nB=2\r\n")
    assert el.load_env_file(path) == {"A": "1", "B": "2"}


@pytest.mark.parametrize("line", [
    "lowercase=x", "1BAD=x", "BAD NAME=x", "NO_EQUALS_SIGN", "=novalue", "export X=1", "A-B=x", "X" * 70 + "=x",
    "GOOD=has\x00nul", "GOOD=has\x1bescape",
])
def test_bad_lines_are_ignored_and_never_crash(tmp_path, line):
    path = write_env(tmp_path, line + "\nOK=1\n")
    assert el.load_env_file(path) == {"OK": "1"}


def test_the_value_may_contain_an_equals_sign(tmp_path):
    assert el.load_env_file(write_env(tmp_path, "K=a=b==c\n")) == {"K": "a=b==c"}


def test_a_missing_file_a_folder_or_a_huge_file_give_an_empty_result(tmp_path):
    assert el.load_env_file(tmp_path / "nope.env") == {}
    assert el.load_env_file(tmp_path) == {}
    big = tmp_path / "big.env"
    big.write_text("A=1\n" + "#" * (el.MAX_ENV_BYTES + 10), encoding="utf-8")
    assert el.load_env_file(big) == {}


def test_a_file_that_is_not_utf8_gives_an_empty_result(tmp_path):
    path = tmp_path / "latin.env"
    path.write_bytes(b"A=\xff\xfe\n")
    assert el.load_env_file(path) == {}


def test_a_very_long_value_is_ignored(tmp_path):
    assert el.load_env_file(write_env(tmp_path, "A=" + "x" * 600 + "\nB=ok\n")) == {"B": "ok"}


def test_the_loader_does_not_change_the_process_environment(tmp_path):
    before = dict(os.environ)
    el.load_env_file(write_env(tmp_path, "CRA_TEST_ONLY_VARIABLE=1\n"))
    assert dict(os.environ) == before and "CRA_TEST_ONLY_VARIABLE" not in os.environ


def test_a_real_environment_variable_wins_over_the_file():
    file_values = {"GEMINI_MODEL": "from-file"}
    assert el.get_setting("GEMINI_MODEL", file_values, {"GEMINI_MODEL": "from-env"}) == "from-env"
    assert el.get_setting("GEMINI_MODEL", file_values, {}) == "from-file"
    assert el.get_setting("GEMINI_MODEL", {}, {}) is None
    assert el.get_setting("GEMINI_MODEL", {}, {}, default="x") == "x"
    assert el.get_setting("GEMINI_MODEL", file_values, {"GEMINI_MODEL": "  "}) == "from-file"  # blank counts as not set


@pytest.mark.parametrize("key", ["AIza" + "x" * 35, "a-b_c" * 6])
def test_a_plausible_api_key_is_accepted(key):
    assert el.valid_api_key(el.Secret(key))
    assert not el.valid_api_key(key)  # a plain string is never accepted: keys travel boxed


@pytest.mark.parametrize("key", [None, "", "short", "put-your-key-here", "has space " + "x" * 30, "x" * 30 + "\n",
                                 "x" * 30 + "\r\nX-Evil: 1", "x" * 300, 5, b"x" * 30])
def test_a_bad_api_key_is_refused(key):
    assert not el.valid_api_key(el.Secret(key) if isinstance(key, str) else key)


@pytest.mark.parametrize("model", ["gemini-2.5-flash", "gemini-pro", "a.b-c_d"])
def test_a_plausible_model_name_is_accepted(model):
    assert el.valid_model_name(model)


@pytest.mark.parametrize("model", [None, "", "a/b", "a b", "a:generate", "a?x=1", "a\n", "../x", "x" * 100, 5])
def test_a_model_name_that_could_change_the_web_address_is_refused(model):
    assert not el.valid_model_name(model)


# ------------------------------------------------------------------ the Secret box (the key must never be printed)

KEY = "AIzaSyFAKE-KEY-FOR-TESTS-0123456789abcdef"


def test_a_secret_never_shows_its_value_in_any_text_form():
    import copy
    import json
    import logging
    import pickle
    box = el.Secret(KEY)
    for shown in (str(box), repr(box), f"{box}", "%s" % box, "%r" % box, format(box, ">40"), repr([box]), repr({"k": box}),
                  repr((box,)), str({"x-goog-api-key": box})):
        assert KEY not in shown and "***" in shown
    with pytest.raises(TypeError):
        pickle.dumps(box)
    with pytest.raises(TypeError):
        copy.copy(box)
    with pytest.raises(TypeError):
        json.dumps(box)
    logging.getLogger("cra-test").warning("key=%s", box)  # must not raise; the value can never be formatted in
    assert box.reveal() == KEY
    with pytest.raises(AttributeError):
        box._value = "other"
    with pytest.raises(AttributeError):
        box.other = 1
    with pytest.raises(TypeError):
        el.Secret(5)


def test_a_secret_equals_only_another_secret_never_a_plain_string():
    assert el.Secret(KEY) == el.Secret(KEY) and el.Secret(KEY) != KEY and el.Secret(KEY) != el.Secret(KEY + "x")


def test_get_secret_returns_a_box_or_nothing():
    box = el.get_secret("GEMINI_API_KEY", {}, {"GEMINI_API_KEY": " " + KEY + " "})
    assert isinstance(box, el.Secret) and box.reveal() == KEY and KEY not in repr(box)
    assert el.get_secret("GEMINI_API_KEY", {}, {}) is None
