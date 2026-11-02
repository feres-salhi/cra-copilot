"""Phase 4 piece 1: the case data model (cases/<case-id>/ with facts.json, draft.md, check.json, case.json)."""

import json
import os
from datetime import datetime, timezone

import pytest

from src import cases, report_facts, report_writer
from src.matcher import REPORT_CASE_LABEL  # noqa: F401  (the label must still exist)

PRODUCT = {"manufacturer": "Musterfirma GmbH (fictional)", "product_name": "SmartHeat X1", "member_states": ["DE", "AT"]}
FINDING = {
    "action": "REPORT_CASE", "status": "AFFECTED", "exploited": True, "exploited_via": "kev",
    "exploited_cve": "CVE-2021-44228", "exploited_cve_matched_on": "alias", "cve_ids": ["CVE-2021-44228"],
    "component": "log4j-core", "version": "2.14.1",
}
KEV_IDS = {"CVE-2021-44228"}
AWARE = datetime(2026, 11, 2, 9, 30, tzinfo=timezone.utc)


def make_facts(awareness=AWARE):
    return report_facts.build_facts(PRODUCT, FINDING, KEV_IDS, awareness=awareness)


def make_draft(facts):
    return report_writer.build_draft(facts, None)


def meta_for(facts):
    return cases.new_meta(created_at=datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc), origin={"run_file": "x.json"})


def create(tmp_path, facts=None):
    facts = facts or make_facts()
    draft = make_draft(facts)
    case_id = cases.create_case(tmp_path / "cases", facts, draft.reports, draft.check, draft.source, meta_for(facts))
    return case_id, facts, draft


# ---------------------------------------------------------------- case ids


@pytest.mark.parametrize("good", ["case-0123456789ab", "case-ffffffffffff"])
def test_good_case_ids_are_accepted(good):
    assert cases.check_case_id(good) == good


@pytest.mark.parametrize("bad", [
    "", "case-", "case-0123456789a", "case-0123456789abc", "case-0123456789AB", "CASE-0123456789ab",
    "../case-0123456789ab", "case-0123456789ab/..", "case-0123456789ab\n", "case-0123456789ab ", "case-0123456789ag",
    "case-0123456789ab\x00", "C:\\case-0123456789ab", "case-0123456789ab.json", "con", "..", ".", None, 12, ["case-0123456789ab"],
])
def test_bad_case_ids_are_refused_before_any_path_is_built(bad):
    with pytest.raises(cases.CaseError):
        cases.check_case_id(bad)
    with pytest.raises(cases.CaseError):
        cases.case_path("somewhere", bad)


def test_case_id_is_made_from_the_facts_and_stable():
    facts = make_facts()
    assert cases.make_case_id(facts) == cases.make_case_id(make_facts(datetime(2026, 11, 3, 1, 0, tzinfo=timezone.utc)))
    other = dict(FINDING, version="2.15.0")
    assert cases.make_case_id(facts) != cases.make_case_id(report_facts.build_facts(PRODUCT, other, KEV_IDS, awareness=AWARE))
    assert cases.CASE_ID.fullmatch(cases.make_case_id(facts))


# ---------------------------------------------------------------- creating and loading


def test_a_case_has_the_four_files_and_status_pending(tmp_path):
    case_id, facts, _ = create(tmp_path)
    folder = tmp_path / "cases" / case_id
    assert sorted(p.name for p in folder.iterdir()) == ["case.json", "check.json", "draft.md", "facts.json"]
    case = cases.load_case(tmp_path / "cases", case_id)
    assert case.meta["status"] == "PENDING"
    assert case.facts == facts
    assert case.check["status"] == "PASS"
    assert case.check["source"]["mode"] == "fallback"


def test_draft_md_holds_english_and_german_in_one_plain_file(tmp_path):
    case_id, _, draft = create(tmp_path)
    text = (tmp_path / "cases" / case_id / "draft.md").read_text(encoding="utf-8")
    assert text.startswith(cases.EN_MARK + "\n")
    assert text.index(cases.EN_MARK) < text.index(cases.DE_MARK)
    assert draft.reports["en"] in text and draft.reports["de"] in text
    assert "<" not in text.replace("<>", "")  # plain text, no HTML
    case = cases.load_case(tmp_path / "cases", case_id)
    assert case.reports == draft.reports


def test_split_and_join_are_exact_inverses_and_strict():
    reports = {"en": "A\nB\n", "de": "C\nD\n"}
    assert cases.split_draft(cases.join_draft(reports)) == reports
    for broken in ("", "no marks", cases.EN_MARK + "\nA\n", cases.join_draft(reports) + cases.DE_MARK + "\nE\n",
                   cases.join_draft(reports).replace(cases.DE_MARK, cases.EN_MARK)):
        with pytest.raises(cases.CaseError):
            cases.split_draft(broken)


def test_the_same_case_cannot_be_created_twice(tmp_path):
    create(tmp_path)
    with pytest.raises(cases.CaseExists):
        create(tmp_path)


def test_a_failed_check_is_never_written_as_a_case(tmp_path):
    facts = make_facts()
    draft = make_draft(facts)
    bad_check = type(draft.check)(problems=["something is wrong"])
    with pytest.raises(cases.CaseError):
        cases.create_case(tmp_path / "cases", facts, draft.reports, bad_check, draft.source, meta_for(facts))
    assert not (tmp_path / "cases").exists() or not list((tmp_path / "cases").iterdir())


def test_a_crash_while_writing_leaves_no_half_case(tmp_path, monkeypatch):
    facts = make_facts()
    draft = make_draft(facts)
    real = cases._write_text
    calls = {"n": 0}

    def flaky(path, text):
        calls["n"] += 1
        if calls["n"] == 3:
            raise OSError("disk full")
        real(path, text)

    monkeypatch.setattr(cases, "_write_text", flaky)
    with pytest.raises(OSError):
        cases.create_case(tmp_path / "cases", facts, draft.reports, draft.check, draft.source, meta_for(facts))
    assert list((tmp_path / "cases").iterdir()) == []
    monkeypatch.setattr(cases, "_write_text", real)
    cases.create_case(tmp_path / "cases", facts, draft.reports, draft.check, draft.source, meta_for(facts))  # can be created now


def test_facts_without_awareness_cannot_become_a_case(tmp_path):
    facts = make_facts(awareness=None)
    draft = make_draft(facts)
    with pytest.raises(cases.CaseError):
        cases.create_case(tmp_path / "cases", facts, draft.reports, draft.check, draft.source, meta_for(facts))


def test_load_refuses_unknown_missing_and_tampered_cases(tmp_path):
    case_id, facts, _ = create(tmp_path)
    root = tmp_path / "cases"
    with pytest.raises(cases.CaseError):
        cases.load_case(root, "case-000000000000")  # does not exist
    with pytest.raises(cases.CaseError):
        cases.load_case(root, "../cases")
    folder = root / case_id
    # facts.json that is not valid facts
    original = (folder / "facts.json").read_text(encoding="utf-8")
    (folder / "facts.json").write_text(json.dumps({**facts, "cve_id": "nope"}), encoding="utf-8")
    with pytest.raises(cases.CaseError):
        cases.load_case(root, case_id)
    # facts.json of ANOTHER case under this id
    other = dict(facts, version="9.9.9")
    other["title"] = report_facts._titles(other["product_name"], other["component"], other["version"], other["cve_id"])
    (folder / "facts.json").write_text(json.dumps(other), encoding="utf-8")
    with pytest.raises(cases.CaseError):
        cases.load_case(root, case_id)
    (folder / "facts.json").write_text(original, encoding="utf-8")
    # unknown status
    meta = json.loads((folder / "case.json").read_text(encoding="utf-8"))
    (folder / "case.json").write_text(json.dumps({**meta, "status": "SENT"}), encoding="utf-8")
    with pytest.raises(cases.CaseError):
        cases.load_case(root, case_id)
    (folder / "case.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(cases.CaseError):
        cases.load_case(root, case_id)


def test_load_refuses_huge_files_and_a_missing_file(tmp_path):
    case_id, _, _ = create(tmp_path)
    folder = tmp_path / "cases" / case_id
    (folder / "draft.md").write_text("x" * (cases.MAX_FILE_BYTES + 1), encoding="utf-8")
    with pytest.raises(cases.CaseError):
        cases.load_case(tmp_path / "cases", case_id)
    (folder / "draft.md").unlink()
    with pytest.raises(cases.CaseError):
        cases.load_case(tmp_path / "cases", case_id)


def test_load_keeps_the_exact_bytes_hashes(tmp_path):
    import hashlib
    case_id, _, _ = create(tmp_path)
    folder = tmp_path / "cases" / case_id
    case = cases.load_case(tmp_path / "cases", case_id)
    assert case.sha256["draft"] == hashlib.sha256((folder / "draft.md").read_bytes()).hexdigest()
    assert case.sha256["facts"] == hashlib.sha256((folder / "facts.json").read_bytes()).hexdigest()


def test_the_case_folder_is_a_real_folder_not_a_link_or_file(tmp_path):
    root = tmp_path / "cases"
    root.mkdir()
    (root / "case-aaaaaaaaaaaa").write_text("i am a file", encoding="utf-8")
    with pytest.raises(cases.CaseError):
        cases.load_case(root, "case-aaaaaaaaaaaa")


def test_list_cases_returns_only_valid_cases_and_survives_junk(tmp_path):
    case_id, _, _ = create(tmp_path)
    root = tmp_path / "cases"
    (root / "not-a-case").mkdir()
    (root / "case-bbbbbbbbbbbb").mkdir()  # empty folder: unreadable case
    (root / "approvals.log").write_text("", encoding="utf-8")
    found, unreadable = cases.list_cases(root)
    assert [c.case_id for c in found] == [case_id]
    assert unreadable == ["case-bbbbbbbbbbbb"]
    assert cases.list_cases(tmp_path / "missing") == ([], [])


# ---------------------------------------------------------------- the file contents are plain data


def test_files_are_written_as_utf_8_json_without_secrets_or_html(tmp_path):
    case_id, _, _ = create(tmp_path)
    folder = tmp_path / "cases" / case_id
    for name in ("facts.json", "check.json", "case.json"):
        data = json.loads((folder / name).read_text(encoding="utf-8"))
        assert isinstance(data, dict)
    assert os.path.getsize(folder / "draft.md") < cases.MAX_FILE_BYTES


# ---------------------------------------------------------------- after the reviews


def approved_meta(case):
    meta = dict(case.meta, status="APPROVED")
    meta["approval"] = {"approver": "Fares", "approved_at": "2026-11-02T10:00:00+00:00",
                        "draft_sha256": case.sha256["draft"], "facts_sha256": case.sha256["facts"], "sbom_sha256": "a" * 64,
                        "approved_sha256": "b" * 64}
    return meta


def test_an_empty_or_half_approval_record_is_not_accepted(tmp_path):
    case_id, _, _ = create(tmp_path)
    folder = tmp_path / "cases" / case_id
    meta = json.loads((folder / "case.json").read_text(encoding="utf-8"))
    for approval in ({}, {"approver": "x"}, None):
        (folder / "case.json").write_text(json.dumps({**meta, "status": "APPROVED", "approval": approval}), encoding="utf-8")
        with pytest.raises(cases.CaseError):
            cases.load_case(tmp_path / "cases", case_id)
    (folder / "case.json").write_text(json.dumps({**meta, "approval": {"approver": "x"}}), encoding="utf-8")  # PENDING + record
    with pytest.raises(cases.CaseError):
        cases.load_case(tmp_path / "cases", case_id)


def test_save_meta_allows_pending_to_approved_but_never_back(tmp_path):
    case_id, _, _ = create(tmp_path)
    root = tmp_path / "cases"
    case = cases.load_case(root, case_id)
    cases.save_meta(root, case_id, approved_meta(case))
    assert cases.load_case(root, case_id).meta["status"] == "APPROVED"
    with pytest.raises(cases.CaseError):
        cases.save_meta(root, case_id, case.meta)  # PENDING again
    with pytest.raises(cases.CaseError):
        cases.save_meta(root, case_id, {**approved_meta(case), "approval": {}})
    with pytest.raises(cases.CaseError):
        cases.save_meta(root, "case-000000000000", approved_meta(case))


def test_reports_that_would_not_survive_reading_are_refused_before_writing(tmp_path):
    facts = make_facts()
    draft = make_draft(facts)
    for reports in ({"en": draft.reports["en"].rstrip("\n"), "de": draft.reports["de"]},
                    {"en": draft.reports["en"] + cases.DE_MARK + "\n", "de": draft.reports["de"]},
                    {"en": " ", "de": draft.reports["de"]}):
        with pytest.raises(cases.CaseError):
            cases.create_case(tmp_path / "cases", facts, reports, draft.check, draft.source, meta_for(facts))
    assert not (tmp_path / "cases").exists() or list((tmp_path / "cases").iterdir()) == []


def test_check_json_keeps_only_the_known_source_keys(tmp_path):
    facts = make_facts()
    draft = make_draft(facts)
    source = {"mode": "ai", "reason": None, "api_key": "SHOULD-NOT-BE-WRITTEN"}
    case_id = cases.create_case(tmp_path / "cases", facts, draft.reports, draft.check, source, meta_for(facts))
    text = (tmp_path / "cases" / case_id / "check.json").read_text(encoding="utf-8")
    assert "SHOULD-NOT-BE-WRITTEN" not in text and "api_key" not in text


def test_a_leftover_temp_folder_does_not_block_the_case_or_show_up_as_a_case(tmp_path):
    root = tmp_path / "cases"
    (root / ".tmp-leftover").mkdir(parents=True)
    case_id, _, _ = create(tmp_path)
    found, unreadable = cases.list_cases(root)
    assert [c.case_id for c in found] == [case_id] and unreadable == []
