"""Phase 3, piece 6, review round: banners on every path, honest notes, duplicates, cap, failing checks."""

import json

import pytest

from src import cli
from src import news_watcher as nw
from src import report_writer as rw
from tests.test_cli_preview import BANNER, make_run, preview, preview_text, reseal
from tests.test_report_writer_ai import FakeAI


def banners_at_both_ends(out):
    lines = [line for line in out.splitlines() if line.strip()]
    return lines[0] == BANNER and lines[-1] == BANNER


def test_the_banner_is_on_both_ends_even_when_the_run_file_is_rejected(tmp_path, capsys):
    code, out = preview(tmp_path, tmp_path / "nope.json", capsys=capsys)
    assert code == 2 and banners_at_both_ends(out)
    code, out = preview(tmp_path, tmp_path, capsys=capsys)  # a folder instead of a file
    assert code == 2 and banners_at_both_ends(out) and "REJECTED" in out
    code, out = preview_text(tmp_path, "not json", capsys)
    assert code == 2 and banners_at_both_ends(out)


def test_the_banner_is_on_both_ends_when_the_seal_is_wrong_or_the_ai_is_not_configured(tmp_path, capsys, monkeypatch):
    path = make_run(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["product"]["product_name"] = "Edited"
    code, out = preview_text(tmp_path, json.dumps(data), capsys)
    assert code == 2 and banners_at_both_ends(out)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    code, out = preview(tmp_path, path, "--live-ai", capsys=capsys)
    assert code == 2 and banners_at_both_ends(out) and "GEMINI_API_KEY" in out


def test_each_language_block_carries_the_banner_too(tmp_path, capsys):
    code, out = preview(tmp_path, make_run(tmp_path), capsys=capsys)
    assert out.count(f"--- ENGLISH --- ({BANNER})") == out.count("--- ENGLISH ---") > 0
    assert out.count(f"--- DEUTSCH --- ({BANNER})") == out.count("--- DEUTSCH ---") > 0


def test_the_output_says_the_affected_result_is_not_checked_again(tmp_path, capsys):
    code, out = preview(tmp_path, make_run(tmp_path), capsys=capsys)
    assert "not checked against the SBOM again" in out


def test_a_run_that_says_complete_but_has_a_stale_source_is_called_incomplete(tmp_path, capsys):
    data = json.loads(make_run(tmp_path).read_text(encoding="utf-8"))
    data["complete"] = True
    data["sources"]["kev"]["status"] = "stale"
    code, out = preview_text(tmp_path, reseal(data), capsys)
    assert "this run was INCOMPLETE" in out


def test_a_missing_saved_kev_list_is_named_as_the_reason(tmp_path, capsys):
    path = make_run(tmp_path)
    (tmp_path / "cache" / "kev" / "kev-saved.json").unlink()
    code, out = preview(tmp_path, path, capsys=capsys)
    assert code == 1 and "no usable saved KEV list was found" in out


def test_a_saved_kev_list_that_is_newer_than_the_run_is_mentioned(tmp_path, capsys):
    path = make_run(tmp_path)
    saved = tmp_path / "cache" / "kev" / "kev-saved.json"
    data = json.loads(saved.read_text(encoding="utf-8"))
    data["sha256"] = "0" * 64
    saved.write_text(json.dumps(data), encoding="utf-8")
    code, out = preview(tmp_path, path, capsys=capsys)
    assert "is not the one this run used" in out and code == 0


def test_a_case_that_cannot_be_shown_is_named(tmp_path, capsys):
    data = json.loads(make_run(tmp_path).read_text(encoding="utf-8"))
    finding = next(f for f in data["result"]["findings"] if f["action"] == "REPORT_CASE")
    finding["exploited_cve"] = "CVE-2099-99999"
    finding["cve_ids"].append("CVE-2099-99999")
    code, out = preview_text(tmp_path, reseal(data), capsys)
    assert "(log4j-core / CVE-2099-99999)" in out


def test_duplicate_findings_are_shown_once_and_counted(tmp_path, capsys):
    data = json.loads(make_run(tmp_path).read_text(encoding="utf-8"))
    findings = data["result"]["findings"]
    cases = [f for f in findings if f["action"] == "REPORT_CASE"]
    findings.append(dict(cases[0]))
    findings.append(dict(cases[0]))
    code, out = preview_text(tmp_path, reseal(data), capsys)
    _, plain = preview(tmp_path, make_run_again(tmp_path), capsys=capsys)
    assert out.count("--- ENGLISH ---") == plain.count("--- ENGLISH ---")
    assert "2 more advisory entries lead to a case that is shown above" in out


def make_run_again(tmp_path):
    (path,) = (tmp_path / "runs").glob("*.json")
    return path


def test_the_number_of_shown_cases_is_capped_and_the_cap_is_reported(tmp_path, capsys, monkeypatch):
    path = make_run(tmp_path)
    monkeypatch.setattr(cli, "MAX_PREVIEW_CASES", 1)
    ai = FakeAI()
    code, out = preview(tmp_path, path, "--live-ai", ai=ai, capsys=capsys)
    assert out.count("--- ENGLISH ---") == 1 and "further case(s) were not shown" in out and code == 1
    assert len(ai.prompts) == 2  # one case, two languages: the cap also limits AI calls


def test_a_failing_fact_check_gives_exit_code_1_and_no_report_text(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(rw, "FALLBACK", {"en": "This is safe.", "de": "Das ist sicher."})
    code, out = preview(tmp_path, make_run(tmp_path), capsys=capsys)
    assert code == 1 and "Fact check: FAIL" in out and "--- ENGLISH ---" not in out
    assert banners_at_both_ends(out)


def test_an_unexpected_error_while_writing_a_draft_is_reported_without_a_traceback(tmp_path, capsys, monkeypatch):
    def boom(facts, ai=None):
        raise ValueError("leakcheck-secret")

    monkeypatch.setattr(rw, "build_draft", boom)
    code, out = preview(tmp_path, make_run(tmp_path), capsys=capsys)
    assert code == 1 and "could not be written (ValueError)" in out
    assert "leakcheck-secret" not in out and "Traceback" not in out and banners_at_both_ends(out)


def test_a_control_character_in_an_ai_answer_never_reaches_the_screen(tmp_path, capsys):
    bad = {"en": "{product_name} contains {component}.\x1b[2J", "de": "{product_name} enthält {component}.\x07"}
    code, out = preview(tmp_path, make_run(tmp_path), "--live-ai", ai=FakeAI(answers=bad), capsys=capsys)
    assert "\x1b" not in out and "\x07" not in out
    assert "fixed fallback text (the AI text was rejected" in out
