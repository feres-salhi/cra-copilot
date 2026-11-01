"""Regression tests for the leak found in the live test: pytest printed the full API key in a traceback.

The old code passed the key as a plain string through gemini_generate and http_fetch, so a failing request showed it in
str(), repr(), the exception chain and the pytest traceback. Every test here FAILS on the old code and passes now.
All offline: a fake network that always fails, never the real Gemini API.
"""

import traceback
from pathlib import Path

import pytest

from src import env_loader as el
from src import news_watcher as nw
from src import report_writer as rw

KEY = "AIzaSyLEAKCHECK-0123456789abcdefghij"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
pytest_plugins = ["pytester"]


def failing_fetch(url, body=None, max_bytes=0, headers=None, allowed_hosts=None):
    raise nw.FetchError("HTTP 403", 403)


def test_a_failing_request_does_not_show_the_key_in_str_repr_the_exception_or_its_traceback_text():
    with pytest.raises(nw.FetchError) as caught:
        rw.gemini_generate("p", el.Secret(KEY), "gemini-3.5-flash", failing_fetch)
    text = "".join(traceback.format_exception(caught.value)) + str(caught.value) + repr(caught.value)
    # locals of every frame in the chain (what `pytest -l` / showlocals would print)
    tb = caught.value.__traceback__
    while tb is not None:
        text += repr(tb.tb_frame.f_locals)
        tb = tb.tb_next
    assert KEY not in text


def test_make_gemini_ai_keeps_the_key_boxed_all_the_way(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(f"GEMINI_API_KEY={KEY}\n", encoding="utf-8")
    seen = {}

    def spy(url, body=None, max_bytes=0, headers=None, allowed_hosts=None):
        seen["headers"] = headers
        raise nw.FetchError("HTTP 400", 400)

    ai = rw.make_gemini_ai(env_path=env_file, environ={}, fetch=spy)
    with pytest.raises(nw.FetchError):
        ai("prompt")
    value = seen["headers"]["x-goog-api-key"]
    assert isinstance(value, el.Secret) and KEY not in repr(seen["headers"])
    assert all(not isinstance(cell.cell_contents, str) or KEY not in cell.cell_contents for cell in ai.__closure__)  # no plain copy


def test_a_pytest_traceback_with_showlocals_does_not_print_the_key(pytester, monkeypatch):
    """The real case (the child test file never contains the key as text: pytest prints source lines): a test fails inside the request code; pytest runs with -l (show locals) and --tb=long."""
    pytester.makepyfile(f"""
        import os
        from src import env_loader as el
        from src import news_watcher as nw
        from src import report_writer as rw

        def broken(url, body=None, max_bytes=0, headers=None, allowed_hosts=None):
            raise nw.FetchError("HTTP 403", 403)

        def test_fails_on_purpose():
            key = el.Secret(os.environ["LEAKCHECK_KEY"])
            rw.gemini_generate("p", key, "gemini-3.5-flash", broken)

        def test_fails_inside_http_fetch(monkeypatch):
            class Boom:
                def open(self, request, timeout=None):
                    raise OSError("boom")
            monkeypatch.setattr(nw.urllib.request, "build_opener", lambda *h: Boom())
            nw.http_fetch("https://generativelanguage.googleapis.com/v1beta/models/m:generateContent", b"{{}}", 100,
                          headers={{"x-goog-api-key": el.Secret(os.environ["LEAKCHECK_KEY"])}}, allowed_hosts={{"generativelanguage.googleapis.com"}})
    """)
    monkeypatch.setenv("LEAKCHECK_KEY", KEY)  # given by environment, so the key is not written in the test source
    monkeypatch.setenv("PYTHONPATH", str(PROJECT_ROOT))  # the sub-process must find our `src` package
    result = pytester.runpytest_subprocess("-l", "-vv", "--tb=long", "-p", "no:cacheprovider")
    result.assert_outcomes(failed=2)
    output = result.stdout.str() + result.stderr.str()
    assert KEY not in output and "FetchError" in output


def test_the_old_way_a_plain_string_key_is_now_refused_and_the_http_layer_refuses_it_too():
    with pytest.raises(ValueError) as caught:
        rw.gemini_generate("p", KEY, "gemini-3.5-flash", failing_fetch)
    assert KEY not in str(caught.value)
    with pytest.raises(nw.FetchError) as caught:
        nw.http_fetch("https://generativelanguage.googleapis.com/x", b"{}", 100, headers={"x-goog-api-key": KEY},
                      allowed_hosts={"generativelanguage.googleapis.com"})
    assert KEY not in str(caught.value)


def test_the_live_test_prints_only_the_error_type_and_status():
    from tests import test_live_ai as live
    assert live.describe_error(nw.FetchError("HTTP 403 " + KEY, 403)) == "FetchError (HTTP status 403)"
    assert live.describe_error(ValueError(KEY)) == "ValueError"
    assert KEY not in live.describe_error(RuntimeError(KEY))


def test_the_detector_works_a_plain_string_key_in_a_failing_test_DOES_show_with_showlocals(pytester, monkeypatch):
    monkeypatch.setenv("LEAKCHECK_KEY", KEY)
    """Proof that the traceback test above can fail: with a plain string the same run prints the key."""
    pytester.makepyfile("""
        import os
        def test_fails():
            key = os.environ["LEAKCHECK_KEY"]
            raise RuntimeError("boom")
    """)
    result = pytester.runpytest_subprocess("-l", "-vv", "--tb=long", "-p", "no:cacheprovider")
    assert KEY in result.stdout.str()


def all_text(error):
    """Everything pytest -l -vv could print for this error: the traceback text, the locals of every frame, the chain."""
    text = ""
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        text += "".join(traceback.format_exception(error, chain=False)) + repr(error)
        tb = error.__traceback__
        while tb is not None:
            text += repr(tb.tb_frame.f_locals)
            tb = tb.tb_next
        error = error.__cause__ or error.__context__
    return text


def test_a_REAL_urllib_failure_leaves_no_frame_that_holds_the_key():
    """Nothing listens on localhost:443, so the real opener, urllib and http.client frames run and fail
    (old code: their locals held 'X-Goog-Api-Key: <key>' and pytest -l -vv printed it). No outside network is used."""
    with pytest.raises(nw.FetchError) as caught:
        nw.http_fetch("https://localhost/x", b"{}", 100, headers={"x-goog-api-key": el.Secret(KEY)}, allowed_hosts={"localhost"})
    assert "network problem" in str(caught.value) or "HTTP" in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__context__ is None and KEY not in all_text(caught.value)


def test_make_gemini_ai_with_the_key_in_the_environment_and_a_bad_model_shows_no_key_in_any_frame():
    with pytest.raises(rw.AiNotConfigured) as caught:  # the dict is built inline: this test's own frame must not hold it
        rw.make_gemini_ai(env_path=Path("does-not-exist.env"), environ={"GEMINI_API_KEY": KEY, "GEMINI_MODEL": "bad/model"})
    text = all_text(caught.value)
    assert KEY not in text and "GEMINI_MODEL" in str(caught.value)


def test_only_a_short_list_of_headers_may_be_plain_text_every_other_header_must_be_a_secret():
    for name in ("x-api-key", "api-key", "x-auth-token", "X-Goog-Api-Key", "Authorization"):
        with pytest.raises(nw.FetchError):
            nw.http_fetch("https://generativelanguage.googleapis.com/x", b"{}", 100, headers={name: KEY},
                          allowed_hosts={"generativelanguage.googleapis.com"})


def test_a_pytest_run_with_the_key_in_the_environment_and_a_real_urllib_failure_prints_no_key(pytester, monkeypatch):
    """The whole real case under -l -vv: the key sits in the process environment (as GEMINI_API_KEY), the opener is the
    real one and fails."""
    pytester.makepyfile("""
        from src import report_writer as rw

        def test_fails_for_real():
            ai = rw.make_gemini_ai(env_path="no-such.env")
            def local_fetch(url, body=None, max_bytes=0, headers=None, allowed_hosts=None):
                from src import news_watcher as nw
                return nw.http_fetch("https://localhost/x", body, max_bytes, headers=headers, allowed_hosts={"localhost"})
            rw.gemini_generate("p", rw.env_loader.get_secret("GEMINI_API_KEY", {}, __import__("os").environ), "gemini-3.5-flash", local_fetch)
    """)
    monkeypatch.setenv("GEMINI_API_KEY", KEY)
    monkeypatch.setenv("PYTHONPATH", str(PROJECT_ROOT))
    result = pytester.runpytest_subprocess("-l", "-vv", "--tb=long", "-p", "no:cacheprovider")
    result.assert_outcomes(failed=1)
    output = result.stdout.str() + result.stderr.str()
    assert KEY not in output and "FetchError" in output
