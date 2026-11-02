"""Phase 4 piece 4: `cra approve <case-id>`. The human reads the full text, types the case id and a name; nothing skips this."""

import ast
import hashlib
import json
from pathlib import Path

import pytest

from src import cases, report_facts
from src.cli import main
from tests.test_cli_draft import GOOD_BEFORE_RUN, Keyboard, LATER, draft
from tests.test_cli_run import CONFIG, SBOM, run_cli

NAME = "Fares Salhi"


@pytest.fixture
def world(tmp_path):
    """A real (fake-network) run, and a PENDING case drafted from it."""
    run_cli(tmp_path)
    (run_file,) = (tmp_path / "runs").glob("*.json")
    wrapped = (tmp_path, run_file)
    assert draft(wrapped, Keyboard(GOOD_BEFORE_RUN, "yes")) == 0
    (case_dir,) = (tmp_path / "cases").iterdir()
    return tmp_path, case_dir.name


def approve(world, keyboard, case_id=None, extra=(), now=lambda: LATER):
    tmp_path, default_id = world
    args = ["approve", default_id if case_id is None else case_id, "--cases", str(tmp_path / "cases"), "--cache", str(tmp_path / "cache"),
            "--evidence", str(tmp_path / "evidence"), *extra]
    return main(args, ask=keyboard, now=now)


def good_answers(case_id):
    return [case_id, "yes", NAME]


def load(world):
    return cases.load_case(world[0] / "cases", world[1])


def folder(world):
    return world[0] / "cases" / world[1]


def log_lines(world):
    path = world[0] / "cases" / "approvals.log"
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


# ---------------------------------------------------------------- the happy path


def test_approval_shows_the_full_text_asks_three_questions_and_records_everything(world, capsys):
    capsys.readouterr()
    keyboard = Keyboard(*good_answers(world[1]))
    assert approve(world, keyboard) == 0
    out = capsys.readouterr().out
    case = load(world)
    # the human saw both full texts and the key values
    assert case.reports["en"].strip().splitlines()[3] in out and case.reports["de"].strip().splitlines()[3] in out
    assert "--- ENGLISH ---" in out and "--- DEUTSCH ---" in out
    assert "log4j-core 2.14.1" in out and "CVE-2021-44228" in out
    assert len(keyboard.questions) == 3 and keyboard.answers == []
    # what was saved
    assert case.meta["status"] == "APPROVED"
    approval = case.meta["approval"]
    assert approval["approver"] == NAME
    assert approval["draft_sha256"] == hashlib.sha256((folder(world) / "draft.md").read_bytes()).hexdigest()
    assert approval["facts_sha256"] == hashlib.sha256((folder(world) / "facts.json").read_bytes()).hexdigest()
    assert approval["sbom_sha256"] == hashlib.sha256(Path(SBOM).read_bytes()).hexdigest()
    assert approval["approved_sha256"] == hashlib.sha256((folder(world) / "approved.md").read_bytes()).hexdigest()
    assert "Nothing was sent" in out and "submits it by hand" in out


def test_exactly_one_line_is_added_to_approvals_log(world):
    approve(world, Keyboard(*good_answers(world[1])))
    lines = log_lines(world)
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["case_id"] == world[1] and entry["approver"] == NAME
    assert set(entry) == {"time", "case_id", "approver", "draft_sha256", "facts_sha256", "sbom_sha256", "approved_sha256"}


def test_the_draft_stays_as_it_was_and_approved_md_is_made_by_code(world):
    before = (folder(world) / "draft.md").read_bytes()
    approve(world, Keyboard(*good_answers(world[1])))
    assert (folder(world) / "draft.md").read_bytes() == before
    approved = (folder(world) / "approved.md").read_text(encoding="utf-8")
    assert "NOT APPROVED" not in approved and "NICHT FREIGEGEBEN" not in approved
    assert "APPROVED BY A HUMAN" in approved and "FREIGEGEBEN DURCH EINEN MENSCHEN" in approved
    assert "sends nothing" in approved and "versendet nichts" in approved
    draft_lines = before.decode("utf-8").splitlines()
    approved_lines = approved.splitlines()
    differing = [i for i, (a, b) in enumerate(zip(draft_lines, approved_lines)) if a != b]
    assert len(draft_lines) == len(approved_lines) and len(differing) == 4  # 2 headings + 2 footers, nothing else
    assert str(NAME) not in approved  # no free text in the report


# ---------------------------------------------------------------- the questions cannot be skipped


@pytest.mark.parametrize("answers", [
    ["case-000000000000", "yes", NAME],   # wrong case id
    ["", "yes", NAME],
    ["{id}", "y", NAME], ["{id}", "YES", NAME], ["{id}", "", NAME], ["{id}", "no", NAME],
    ["{id}", "yes", ""], ["{id}", "yes", "   "], ["{id}", "yes", "x" * 200], ["{id}", "yes", "bad\tname"],
    ["{id} ", "yes", NAME],
])
def test_a_wrong_answer_cancels_and_changes_nothing(world, answers, capsys):
    answers = [a.replace("{id}", world[1]) for a in answers]
    assert approve(world, Keyboard(*answers)) == 1
    assert "Cancelled" in capsys.readouterr().out
    assert load(world).meta["status"] == "PENDING"
    assert log_lines(world) == [] and not (folder(world) / "approved.md").exists()


def test_a_piped_input_or_scheduled_task_cannot_approve(world):
    tmp_path, case_id = world
    args = ["approve", case_id, "--cases", str(tmp_path / "cases"), "--cache", str(tmp_path / "cache"),
            "--evidence", str(tmp_path / "evidence")]
    assert main(args, now=lambda: LATER) == 1  # pytest's stdin is not a keyboard
    assert load(world).meta["status"] == "PENDING"


@pytest.mark.parametrize("flag", [["--yes"], ["-y"], ["--force"], ["--name", NAME], ["--approver", NAME], ["--no-input"],
                                  ["--confirm"], ["--send"], ["--non-interactive"], ["--case-id", "x"]])
def test_no_flag_can_answer_for_the_human(world, flag):
    with pytest.raises(SystemExit):
        approve(world, Keyboard(), extra=flag)


# ---------------------------------------------------------------- the case id


@pytest.mark.parametrize("bad", ["../x", "case-zz", "", "case-0123456789ab/..", "CASE-0123456789AB", "con", "case-0123456789ab\n"])
def test_a_bad_case_id_is_rejected_before_any_path_is_built(world, bad, capsys):
    assert approve(world, Keyboard(), case_id=bad) == 2
    assert "REJECTED" in capsys.readouterr().out


def test_an_unknown_case_is_rejected(world, capsys):
    assert approve(world, Keyboard(), case_id="case-000000000000") == 2
    assert "REJECTED" in capsys.readouterr().out


# ---------------------------------------------------------------- the checks the tool does itself


def test_forged_facts_are_found_by_the_rebuild(world, capsys):
    facts = json.loads((folder(world) / "facts.json").read_text(encoding="utf-8"))
    facts["member_states"] = ["DE", "AT", "FR", "IT"]  # a valid-looking change
    (folder(world) / "facts.json").write_text(json.dumps(facts), encoding="utf-8")
    capsys.readouterr()
    assert approve(world, Keyboard(*good_answers(world[1]))) == 1
    out = capsys.readouterr().out
    assert "not the product the run used" in out  # the config no longer gives the Member States of these facts
    assert load_status(world) == "PENDING"


def test_facts_that_differ_from_the_rebuilt_facts_are_refused_and_named(world, capsys, monkeypatch):
    real = report_facts.build_facts

    def other(*args, **kwargs):
        facts = real(*args, **kwargs)
        return {**facts, "version": "9.9.9"}

    monkeypatch.setattr(report_facts, "build_facts", other)
    capsys.readouterr()
    assert approve(world, Keyboard(*good_answers(world[1]))) == 1
    out = capsys.readouterr().out
    assert "differ" in out and "version" in out
    assert load_status(world) == "PENDING"


def load_status(world):
    return json.loads((folder(world) / "case.json").read_text(encoding="utf-8"))["status"]


def test_a_tampered_draft_is_found_by_the_checker_even_if_check_json_says_pass(world, capsys):
    path = folder(world) / "draft.md"
    text = path.read_bytes().decode("utf-8")
    path.write_bytes(text.replace("log4j-core 2.14.1", "log4j-core 9.9.9", 1).encode("utf-8"))
    check = json.loads((folder(world) / "check.json").read_text(encoding="utf-8"))
    assert check["status"] == "PASS"
    capsys.readouterr()
    assert approve(world, Keyboard(*good_answers(world[1]))) == 1
    out = capsys.readouterr().out
    assert "fact check" in out.lower() and "FAIL" in out
    assert load_status(world) == "PENDING"


def test_a_failed_check_json_is_ignored_when_everything_is_fine(world):
    check_path = folder(world) / "check.json"
    check = json.loads(check_path.read_text(encoding="utf-8"))
    check["status"] = "FAIL"
    check["problems"] = ["old news"]
    check_path.write_text(json.dumps(check), encoding="utf-8")
    assert approve(world, Keyboard(*good_answers(world[1]))) == 0


def test_a_changed_sbom_is_refused(world, capsys, tmp_path):
    from tests.test_cli_run import write_sbom
    other_dir = tmp_path / "o"
    other_dir.mkdir()
    other = write_sbom(other_dir, ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"])
    capsys.readouterr()
    assert approve(world, Keyboard(*good_answers(world[1])), extra=["--sbom", other]) == 1
    assert "not the SBOM" in capsys.readouterr().out


def test_a_cve_that_left_the_saved_kev_list_is_refused(world, capsys):
    path = world[0] / "cache" / "kev" / "kev-saved.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    saved["data"]["vulnerabilities"] = [v for v in saved["data"]["vulnerabilities"] if v["cveID"] != "CVE-2021-44228"]
    saved["data"]["count"] = len(saved["data"]["vulnerabilities"])
    path.write_text(json.dumps(saved), encoding="utf-8")
    capsys.readouterr()
    assert approve(world, Keyboard(*good_answers(world[1]))) == 1
    assert "could not be re-derived" in capsys.readouterr().out
    assert load_status(world) == "PENDING"


def test_an_awareness_time_in_the_future_is_refused_at_approval(world, capsys):
    from datetime import timedelta
    capsys.readouterr()
    assert approve(world, Keyboard(*good_answers(world[1])), now=lambda: LATER - timedelta(hours=3, minutes=30)) == 1
    assert "future" in capsys.readouterr().out
    assert load_status(world) == "PENDING"


def test_a_missing_member_states_list_is_refused(world):
    facts = json.loads((folder(world) / "facts.json").read_text(encoding="utf-8"))
    facts["member_states"] = []
    (folder(world) / "facts.json").write_text(json.dumps(facts), encoding="utf-8")
    assert approve(world, Keyboard(*good_answers(world[1]))) == 2  # facts.json is not valid: the case cannot even be read
    assert load_status(world) == "PENDING"


def test_a_name_that_reads_like_a_statement_is_warned_about(world, capsys, monkeypatch):
    monkeypatch.setattr(report_facts, "claim_word_warnings", lambda facts: ["product_name"])
    capsys.readouterr()
    approve(world, Keyboard(*good_answers(world[1])))
    assert "reads like a statement" in capsys.readouterr().out


def test_a_passed_deadline_is_a_loud_warning_at_approval_too(world, capsys):
    from datetime import timedelta
    capsys.readouterr()
    assert approve(world, Keyboard(*good_answers(world[1])), now=lambda: LATER + timedelta(days=5)) == 0
    assert "ALREADY PASSED" in capsys.readouterr().out


def test_a_change_while_the_human_is_deciding_aborts_the_approval(world, capsys):
    class Sneaky(Keyboard):
        def __call__(self, question):
            if len(self.questions) == 2:  # between the second and the third question someone edits the draft
                path = folder(world) / "draft.md"
                path.write_bytes(path.read_bytes() + b" ")
            return super().__call__(question)

    capsys.readouterr()
    assert approve(world, Sneaky(*good_answers(world[1]))) == 1
    assert "changed while you were deciding" in capsys.readouterr().out
    assert load_status(world) == "PENDING" and log_lines(world) == []


# ---------------------------------------------------------------- after approval


def test_approving_twice_without_a_change_asks_nothing_and_logs_nothing_new(world, capsys):
    assert approve(world, Keyboard(*good_answers(world[1]))) == 0
    keyboard = Keyboard()
    capsys.readouterr()
    assert approve(world, keyboard) == 0
    assert "already approved" in capsys.readouterr().out and keyboard.questions == []
    assert len(log_lines(world)) == 1


def test_any_later_edit_means_it_must_be_approved_again(world, capsys):
    approve(world, Keyboard(*good_answers(world[1])))
    assert cases.approval_state(load(world)) == "APPROVED"
    for name in ("draft.md", "facts.json", "approved.md"):
        path = folder(world) / name
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        try:
            try:
                state = cases.approval_state(cases.load_case(world[0] / "cases", world[1]))
            except cases.CaseError:
                state = "CHANGED"
            assert state == "CHANGED", name
        finally:
            path.write_bytes(original)
    assert cases.approval_state(load(world)) == "APPROVED"


def test_an_edited_sbom_after_approval_means_changed(world, tmp_path):
    approve(world, Keyboard(*good_answers(world[1])))
    meta = json.loads((folder(world) / "case.json").read_text(encoding="utf-8"))
    meta["origin"]["sbom"]["path"] = str(tmp_path / "gone.json")
    (folder(world) / "case.json").write_text(json.dumps(meta), encoding="utf-8")
    assert cases.approval_state(load(world)) == "CHANGED"


def test_a_changed_case_can_be_approved_again_and_is_logged_again(world, capsys):
    approve(world, Keyboard(*good_answers(world[1])))
    path = folder(world) / "approved.md"
    path.write_bytes(path.read_bytes() + b"x")
    capsys.readouterr()
    assert approve(world, Keyboard(*good_answers(world[1]))) == 0
    assert "CHANGED since it was approved" in capsys.readouterr().out
    assert len(log_lines(world)) == 2
    assert cases.approval_state(load(world)) == "APPROVED"


# ---------------------------------------------------------------- there is no send function (CLAUDE.md rule 6)


SRC = Path(__file__).parent.parent / "src"
FORBIDDEN_IMPORTS = {"smtplib", "ftplib", "poplib", "imaplib", "telnetlib", "socket", "socketserver", "requests", "httpx",
                     "aiohttp", "webbrowser", "subprocess", "xmlrpc", "paramiko"}
FORBIDDEN_NAME_PARTS = ("send", "submit", "upload", "smtp", "mail", "transmit", "publish", "post_report")


def test_the_code_has_no_send_function_and_no_way_to_send():
    for path in SRC.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                assert not any(part in node.name.lower() for part in FORBIDDEN_NAME_PARTS), (path.name, node.name)
            if isinstance(node, ast.Import):
                assert not ({a.name.split(".")[0] for a in node.names} & FORBIDDEN_IMPORTS), (path.name, "import")
                if any(a.name.startswith("urllib") for a in node.names):
                    assert path.name == "news_watcher.py", (path.name, "only the download module may use urllib")
            if isinstance(node, ast.Call):
                called = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                assert called not in {"sendall", "sendto", "sendmail", "send_message", "system", "popen", "__import__", "startfile"}, (path.name, called)
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in FORBIDDEN_IMPORTS, (path.name, node.module)
                if node.module.startswith("urllib"):
                    assert path.name == "news_watcher.py", (path.name, "only the download module may use urllib")


def test_only_the_news_watcher_and_the_report_writer_touch_the_network():
    users = {p.name for p in SRC.glob("*.py") if "http_fetch(" in p.read_text(encoding="utf-8") or "fetch(" in p.read_text(encoding="utf-8")}
    assert users <= {"news_watcher.py", "report_writer.py", "cli.py", "case_commands.py"}
    for name in ("cases.py", "case_commands.py", "rederive.py", "awareness.py"):
        text = (SRC / name).read_text(encoding="utf-8")
        assert "urlopen" not in text and "http_fetch(" not in text


# ---------------------------------------------------------------- after the reviews


def test_a_refused_re_approval_leaves_the_case_pending_and_removes_the_old_approved_text(world, capsys):
    approve(world, Keyboard(*good_answers(world[1])))
    assert (folder(world) / "approved.md").exists()
    path = folder(world) / "draft.md"
    path.write_bytes(path.read_bytes().decode("utf-8").replace("log4j-core 2.14.1", "log4j-core 9.9.9", 1).encode("utf-8"))
    capsys.readouterr()
    assert approve(world, Keyboard(*good_answers(world[1]))) == 1
    out = capsys.readouterr().out
    assert "CHANGED since it was approved" in out and "Refused" in out
    assert load_status(world) == "PENDING"
    assert not (folder(world) / "approved.md").exists()
    assert len(log_lines(world)) == 1  # the history stays


def test_an_approved_status_without_its_line_in_approvals_log_does_not_count(world):
    approve(world, Keyboard(*good_answers(world[1])))
    assert cases.approval_state(load(world)) == "APPROVED"
    (world[0] / "cases" / "approvals.log").write_text("", encoding="utf-8")
    assert cases.approval_state(load(world)) == "CHANGED"


def test_a_log_line_of_another_person_does_not_count(world):
    approve(world, Keyboard(*good_answers(world[1])))
    log = world[0] / "cases" / "approvals.log"
    entry = json.loads(log.read_text(encoding="utf-8"))
    entry["approver"] = "Somebody Else"
    log.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    assert cases.approval_state(load(world)) == "CHANGED"


def test_a_moved_sbom_can_be_approved_and_stays_approved(world, tmp_path, capsys):
    import shutil
    moved = tmp_path / "moved-sbom.json"
    shutil.copyfile(SBOM, moved)
    assert approve(world, Keyboard(*good_answers(world[1])), extra=["--sbom", str(moved)]) == 0
    assert cases.approval_state(load(world)) == "APPROVED"
    capsys.readouterr()
    assert approve(world, Keyboard()) == 0
    assert "already approved" in capsys.readouterr().out


def test_a_change_of_the_saved_data_while_the_human_is_deciding_aborts(world, capsys):
    class Sneaky(Keyboard):
        def __call__(self, question):
            if len(self.questions) == 2:
                for path in (world[0] / "cache" / "osv-query").glob("*.json"):
                    path.unlink()
            return super().__call__(question)

    capsys.readouterr()
    assert approve(world, Sneaky(*good_answers(world[1]))) == 1
    assert "changed while you were deciding" in capsys.readouterr().out
    assert load_status(world) == "PENDING" and log_lines(world) == []


def test_an_approval_record_with_a_bad_name_or_time_is_not_accepted(world):
    approve(world, Keyboard(*good_answers(world[1])))
    meta = json.loads((folder(world) / "case.json").read_text(encoding="utf-8"))
    for key, value in (("approver", "bad\x1b[31mname"), ("approver", "x" * 200), ("approved_at", "yesterday")):
        broken = json.loads(json.dumps(meta))
        broken["approval"][key] = value
        (folder(world) / "case.json").write_text(json.dumps(broken), encoding="utf-8")
        with pytest.raises(cases.CaseError):
            load(world)


def test_rederive_needs_every_key_of_the_expected_finding(world):
    from src import rederive
    from src.sbom_reader import load_sbom
    components = load_sbom(SBOM).components
    config = json.loads(Path(CONFIG).read_text(encoding="utf-8"))
    with pytest.raises(rederive.RederiveError):
        rederive.rederive(components, config, {"component": "log4j-core"}, world[0] / "cache", world[0] / "evidence", lambda: LATER)
