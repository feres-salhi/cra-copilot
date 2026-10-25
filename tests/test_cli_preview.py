"""Phase 3, piece 6: `cra preview-report --run <run file>` prints the German + English draft of each possible report case.

It saves nothing, sends nothing, and calls the AI only with --live-ai. All tests are offline (fake internet, fake AI).
"""

import json
from pathlib import Path

import pytest

from src import news_watcher as nw
from src import report_writer as rw
from src.cli import main
from tests.test_cli_run import NOW, SBOM, clock, run_cli, saved_run, write_sbom
from tests.test_news_watcher import FakeNet, no_sleep
from tests.test_report_writer_ai import GOOD_AI, SECRET, FakeAI

BANNER = "PREVIEW - NOT A REPORT, NOTHING IS SENT"


def make_run(tmp_path, **kwargs):
    """A real saved run of the fake demo product (offline). Returns the path of the run file."""
    run_cli(tmp_path, **kwargs)
    (path,) = (tmp_path / "runs").glob("*.json")
    return path


def preview(tmp_path, run_path, *extra, ai=None, capsys=None):
    args = ["preview-report", "--run", str(run_path), "--cache", str(tmp_path / "cache"),
            "--evidence", str(tmp_path / "evidence"), "--env-file", str(tmp_path / "no.env"), *extra]
    if capsys:
        capsys.readouterr()  # drop what earlier steps (the demo run) printed
    code = main(args, fetch=FakeNet(), sleep=no_sleep, now=clock, ai=ai)
    return code, capsys.readouterr().out if capsys else ""


def snapshot(folder):
    return sorted((str(p.relative_to(folder)), p.stat().st_size, p.stat().st_mtime_ns) for p in folder.rglob("*") if p.is_file())


def test_the_banner_is_the_first_and_the_last_line(tmp_path, capsys):
    code, out = preview(tmp_path, make_run(tmp_path), capsys=capsys)
    lines = [line for line in out.splitlines() if line.strip()]
    assert lines[0] == BANNER and lines[-1] == BANNER
    assert code == 0


def test_each_possible_report_case_is_shown_once_in_english_and_german(tmp_path, capsys):
    run_path = make_run(tmp_path)
    code, out = preview(tmp_path, run_path, capsys=capsys)
    cases = {(f["component"], f["version"], f["exploited_cve"]) for f in saved_run(tmp_path)["result"]["findings"]
             if f["action"] == "REPORT_CASE"}
    assert len(cases) >= 2 and ("log4j-core", "2.14.1", "CVE-2021-44228") in cases
    assert out.count("--- ENGLISH ---") == len(cases) and out.count("--- DEUTSCH ---") == len(cases)
    for _, _, cve in cases:
        assert f"Vulnerability ID (CVE): {cve}" in out and f"Schwachstellen-ID (CVE): {cve}" in out
    assert out.count("POSSIBLE REPORT CASE") >= len(cases)
    assert "EARLY WARNING - DRAFT" in out and "FRÜHWARNUNG - ENTWURF" in out


def test_the_fact_check_result_and_the_summary_source_are_shown(tmp_path, capsys):
    code, out = preview(tmp_path, make_run(tmp_path), capsys=capsys)
    assert "Fact check: PASS" in out and "Fact check: FAIL" not in out
    assert "Summary written by: fixed fallback text (AI not used (offline mode))" in out
    assert "fixed wording written by code" in out


def test_offline_is_the_default_the_ai_is_never_called_without_the_flag(tmp_path, capsys):
    ai = FakeAI()
    code, out = preview(tmp_path, make_run(tmp_path), ai=ai, capsys=capsys)
    assert ai.prompts == [] and code == 0


def test_with_live_ai_the_ai_is_called_and_its_checked_text_is_used(tmp_path, capsys):
    ai = FakeAI()
    code, out = preview(tmp_path, make_run(tmp_path), "--live-ai", ai=ai, capsys=capsys)
    assert code == 0 and len(ai.prompts) >= 4  # two languages for at least two cases
    assert "Summary written by: AI (checked by code)" in out
    assert "which public sources list as exploited." in out
    assert "no product data is sent" in out
    for prompt in ai.prompts:
        assert "log4j" not in prompt and "SmartHeat" not in prompt and "CVE-" not in prompt


def test_a_rejected_ai_text_falls_back_and_says_why(tmp_path, capsys):
    ai = FakeAI(answers={"en": "The product is secure.", "de": GOOD_AI["de"]})
    code, out = preview(tmp_path, make_run(tmp_path), "--live-ai", ai=ai, capsys=capsys)
    assert code == 0
    assert "fixed fallback text (the AI text was rejected by the fact checker" in out
    assert "Fact check: PASS" in out


def test_live_ai_without_a_key_stops_with_a_clear_message_and_calls_nothing(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    code, out = preview(tmp_path, make_run(tmp_path), "--live-ai", capsys=capsys)
    assert code == 2
    assert "GEMINI_API_KEY" in out and ".env" in out
    assert out.count(BANNER) == 2


def test_the_key_never_shows_up_in_the_output(tmp_path, capsys, monkeypatch):
    env_file = tmp_path / "test.env"
    env_file.write_text(f"GEMINI_API_KEY={SECRET}\n", encoding="utf-8")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    net_calls = []

    def fake_fetch(url, body=None, max_bytes=0, headers=None, allowed_hosts=None):
        net_calls.append(url)
        raise nw.FetchError("HTTP 403", 403)

    monkeypatch.setattr(rw, "http_fetch", fake_fetch)
    args = ["preview-report", "--run", str(make_run(tmp_path)), "--cache", str(tmp_path / "cache"),
            "--evidence", str(tmp_path / "evidence"), "--env-file", str(env_file), "--live-ai"]
    code = main(args, fetch=FakeNet(), sleep=no_sleep, now=clock)
    out = capsys.readouterr().out
    assert code == 0 and net_calls and SECRET not in out
    assert "the AI call failed (FetchError)" in out  # it fell back, and said only the error type


def test_nothing_is_saved_and_nothing_is_changed(tmp_path, capsys):
    run_path = make_run(tmp_path)
    before = snapshot(tmp_path)
    preview(tmp_path, run_path, capsys=capsys)
    preview(tmp_path, run_path, "--live-ai", ai=FakeAI(), capsys=capsys)
    assert snapshot(tmp_path) == before
    assert not (tmp_path / "cases").exists()


def test_there_is_no_option_to_save_or_send(tmp_path):
    for flag in ("--save", "--output", "--send", "--approve", "--yes"):
        with pytest.raises(SystemExit) as stop:
            main(["preview-report", "--run", "x", flag], fetch=FakeNet(), sleep=no_sleep, now=clock)
        assert stop.value.code == 2


def test_the_run_option_is_required():
    with pytest.raises(SystemExit) as stop:
        main(["preview-report"], fetch=FakeNet(), sleep=no_sleep, now=clock)
    assert stop.value.code == 2


def test_an_incomplete_run_is_called_incomplete(tmp_path, capsys):
    code, out = preview(tmp_path, make_run(tmp_path), capsys=capsys)
    assert "this run was INCOMPLETE" in out


def test_a_run_without_a_possible_report_case_says_so(tmp_path, capsys):
    run_path = make_run(tmp_path, sbom=write_sbom(tmp_path, ["pkg:pypi/requests@2.30.0"]))
    code, out = preview(tmp_path, run_path, capsys=capsys)
    assert code == 1 and "No POSSIBLE REPORT CASE in this run" in out
    lines = [line for line in out.splitlines() if line.strip()]
    assert lines[0] == BANNER and lines[-1] == BANNER


# ------------------------------------------------------------------ the run file is not trusted


def preview_text(tmp_path, content, capsys, name="odd.json"):
    path = tmp_path / name
    path.write_bytes(content if isinstance(content, bytes) else content.encode())
    return preview(tmp_path, path, capsys=capsys)


def test_a_missing_or_unreadable_run_file_is_rejected(tmp_path, capsys):
    code, out = preview(tmp_path, tmp_path / "nope.json", capsys=capsys)
    assert code == 2 and "REJECTED" in out
    for content in ("not json", "[]", "{}", b"\xff\xfe", ""):
        code, out = preview_text(tmp_path, content, capsys)
        assert code == 2 and "REJECTED" in out, content


def test_a_run_file_without_a_valid_seal_is_rejected(tmp_path, capsys):
    path = make_run(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["product"]["product_name"] = "Edited Name"  # changed by hand: the seal no longer fits
    code, out = preview_text(tmp_path, json.dumps(data), capsys)
    assert code == 2 and "seal" in out
    del data["seal"]
    code, out = preview_text(tmp_path, json.dumps(data), capsys)
    assert code == 2 and "seal" in out


def test_a_huge_run_file_is_rejected_without_reading_it_all(tmp_path, capsys):
    path = tmp_path / "huge.json"
    path.write_bytes(b" " * (nw.MAX_CACHE_FILE_BYTES + 10))
    code, out = preview(tmp_path, path, capsys=capsys)
    assert code == 2 and "REJECTED" in out


def reseal(data):
    data["seal"] = nw.run_seal(data)
    return json.dumps(data)


def test_a_forged_but_sealed_case_is_still_checked_against_the_real_kev_copy(tmp_path, capsys):
    data = json.loads(make_run(tmp_path).read_text(encoding="utf-8"))
    finding = next(f for f in data["result"]["findings"] if f["action"] == "REPORT_CASE")
    finding["exploited_cve"] = "CVE-2099-99999"
    finding["cve_ids"].append("CVE-2099-99999")
    code, out = preview_text(tmp_path, reseal(data), capsys)  # sealed again: the known S7 limit
    assert code == 1 and "cannot build the facts" in out and "not in the saved KEV list" in out
    assert "Vulnerability ID (CVE): CVE-2099-99999" not in out


def test_without_a_saved_kev_copy_no_kev_based_case_is_shown(tmp_path, capsys):
    run_path = make_run(tmp_path)
    (tmp_path / "cache" / "kev" / "kev-saved.json").unlink()
    code, out = preview(tmp_path, run_path, capsys=capsys)
    assert code == 1 and "cannot build the facts" in out and "--- ENGLISH ---" not in out


def test_odd_values_in_the_run_file_cannot_crash_the_preview_or_inject_terminal_codes(tmp_path, capsys):
    data = json.loads(make_run(tmp_path).read_text(encoding="utf-8"))
    finding = next(f for f in data["result"]["findings"] if f["action"] == "REPORT_CASE")
    finding["component"] = "log4j\x1b[2J-core"
    data["product"]["manufacturer"] = "Evil\x1b]0;title\x07 Corp"
    code, out = preview_text(tmp_path, reseal(data), capsys)
    assert "\x1b" not in out and "\x07" not in out
    assert code == 1 and out.count(BANNER) == 2


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("product"), lambda d: d.update(product="x"), lambda d: d.pop("result"), lambda d: d.update(result=[]),
    lambda d: d["result"].update(findings="x"), lambda d: d["result"].update(findings=[1, None, "x"]),
    lambda d: d.update(complete="yes"),
])
def test_a_run_file_with_the_wrong_shape_never_crashes(tmp_path, capsys, mutate):
    data = json.loads(make_run(tmp_path).read_text(encoding="utf-8"))
    mutate(data)
    code, out = preview_text(tmp_path, reseal(data), capsys)
    assert code in (0, 1, 2) and "Traceback" not in out


def test_everything_printed_is_plain_text(tmp_path, capsys):
    code, out = preview(tmp_path, make_run(tmp_path), "--live-ai", ai=FakeAI(), capsys=capsys)
    assert all(ch == "\n" or ch.isprintable() for ch in out)
