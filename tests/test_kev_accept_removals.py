"""Tests for `cra kev accept-removals` (decision S2): a human accepts a KEV list that lost CVE ids.

Offline: the KEV download is the fake internet from test_news_watcher.
"""

import hashlib
import io
import json
from datetime import timedelta

import pytest

from src import news_watcher as nw
from src.cli import main
from tests.test_news_watcher import NOW, REAL_KEV, FakeNet, _kev_without, no_sleep, now

GONE = ["CVE-2021-44228", "CVE-2021-45046"]


class Asker:
    """A pretend human. Returns the given answers one by one and remembers every question."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.questions = []

    def __call__(self, question):
        self.questions.append(question)
        if not self.answers:
            raise EOFError
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def seed(cache):
    """Save a normal KEV copy, like an earlier `cra run` would."""
    nw.fetch_kev(cache, FakeNet(), no_sleep, now)


def net_without(*ids):
    return FakeNet(kev=json.dumps(_kev_without(*ids)).encode())


def accept(cache, net, asker):
    return main(["kev", "accept-removals", "--cache", str(cache)], fetch=net, sleep=no_sleep, now=now, ask=asker)


def saved_path(cache):
    return cache / "kev" / "kev-saved.json"


def log_path(cache):
    return cache / "kev" / "accepted-removals.log"


def test_nothing_removed_says_so_and_changes_nothing(tmp_path, capsys):
    seed(tmp_path)
    before = saved_path(tmp_path).read_bytes()
    asker = Asker("yes", "Fares")
    assert accept(tmp_path, FakeNet(), asker) == 0
    assert "nothing" in capsys.readouterr().out.lower()
    assert asker.questions == []  # a human is not even asked
    assert saved_path(tmp_path).read_bytes() == before
    assert not log_path(tmp_path).exists()


def test_a_list_that_only_adds_ids_changes_nothing(tmp_path):
    import copy
    seed(tmp_path)
    before = saved_path(tmp_path).read_bytes()
    bigger = copy.deepcopy(REAL_KEV)
    bigger["vulnerabilities"].append({"cveID": "CVE-2099-00010", "dateAdded": "2024-01-01"})
    bigger["count"] = len(bigger["vulnerabilities"])
    asker = Asker("yes", "Fares")
    assert accept(tmp_path, FakeNet(kev=json.dumps(bigger).encode()), asker) == 0
    assert asker.questions == []
    assert saved_path(tmp_path).read_bytes() == before


def test_every_removed_id_is_printed_before_the_question(tmp_path, capsys):
    seed(tmp_path)
    shown_before_question = []
    answers = iter(["no"])

    def ask(question):
        shown_before_question.append(capsys.readouterr().out)
        return next(answers)

    accept(tmp_path, net_without(*GONE), ask)
    assert all(cve in shown_before_question[0] for cve in GONE)


def test_yes_and_a_name_replace_the_saved_copy_and_write_one_log_line(tmp_path):
    seed(tmp_path)
    raw = json.dumps(_kev_without(*GONE)).encode()
    assert accept(tmp_path, FakeNet(kev=raw), Asker("yes", "Fares Salhi")) == 0

    saved = json.loads(saved_path(tmp_path).read_text(encoding="utf-8"))
    assert not set(GONE) & nw.kev_cve_ids(saved["data"])
    assert saved["sha256"] == hashlib.sha256(raw).hexdigest()
    assert saved["downloaded_at"] == NOW.isoformat()

    lines = log_path(tmp_path).read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    count = REAL_KEV["count"]
    assert entry == {"time": NOW.isoformat(), "name": "Fares Salhi", "accepted_ids": GONE,
                     "sha256": hashlib.sha256(raw).hexdigest(),
                     "max_count_before": count, "max_count_after": count - 2}
    assert saved["max_count"] == count - 2  # the smaller, human-accepted list is the new baseline


def test_a_failed_replace_is_marked_in_the_log(tmp_path, monkeypatch, capsys):
    seed(tmp_path)
    before = saved_path(tmp_path).read_bytes()

    def boom(path, data):
        raise OSError("disk full")

    monkeypatch.setattr(nw, "_write_json_atomic", boom)
    assert accept(tmp_path, net_without(*GONE), Asker("yes", "Fares")) == 1
    assert "not changed" in capsys.readouterr().out.lower()
    assert saved_path(tmp_path).read_bytes() == before
    last = json.loads(log_path(tmp_path).read_text(encoding="utf-8").splitlines()[-1])
    assert last["outcome"] == "FAILED"


def test_a_real_keyboard_is_accepted_by_the_default_asker(monkeypatch):
    from src import cli

    class Keyboard(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr("sys.stdin", Keyboard("typed\n"))
    assert cli.ask_human("? ") == "typed"


def test_the_five_percent_dead_end_is_explained(tmp_path, capsys):
    seed(tmp_path)
    many = [e["cveID"] for e in REAL_KEV["vulnerabilities"][:200]]
    accept(tmp_path, net_without(*many), Asker("yes", "Fares"))
    assert "delete cache/kev/kev-saved.json" in capsys.readouterr().out


def test_the_log_grows_by_one_line_for_every_acceptance(tmp_path):
    seed(tmp_path)
    accept(tmp_path, net_without(GONE[0]), Asker("yes", "Fares"))
    accept(tmp_path, net_without(*GONE), Asker("yes", "Fares"))
    assert len(log_path(tmp_path).read_text(encoding="utf-8").splitlines()) == 2


def test_after_acceptance_the_normal_download_is_ok_again(tmp_path):
    seed(tmp_path)
    raw = json.dumps(_kev_without(*GONE)).encode()
    accept(tmp_path, FakeNet(kev=raw), Asker("yes", "Fares"))
    _, status = nw.fetch_kev(tmp_path, FakeNet(kev=raw), no_sleep, now)
    assert status["status"] == "ok"


@pytest.mark.parametrize("answers", [
    ("no", "Fares"),
    ("", "Fares"),
    ("y", "Fares"),
    ("yes please", "Fares"),
    ("Yes", "Fares"),
    ("yes", ""),
    ("yes", "   "),
    ("yes", "Fa\nres"),  # a line break in the name would forge a second log line
    ("yes", "Fa\x1b[2Jres"),
    ("yes", "F" * 500),
    ("yes", EOFError()),
    (EOFError(),),
    (KeyboardInterrupt(),),
])
def test_anything_but_yes_and_a_valid_name_cancels_and_changes_nothing(tmp_path, answers, capsys):
    seed(tmp_path)
    before = saved_path(tmp_path).read_bytes()
    assert accept(tmp_path, net_without(*GONE), Asker(*answers)) == 1
    assert "cancel" in capsys.readouterr().out.lower()
    assert saved_path(tmp_path).read_bytes() == before
    assert not log_path(tmp_path).exists()


def test_a_failed_download_changes_nothing_and_asks_nobody(tmp_path, capsys):
    seed(tmp_path)
    before = saved_path(tmp_path).read_bytes()
    asker = Asker("yes", "Fares")
    assert accept(tmp_path, FakeNet(kev=nw.FetchError("HTTP 503", 503)), asker) == 1
    assert "download failed" in capsys.readouterr().out.lower()
    assert asker.questions == []
    assert saved_path(tmp_path).read_bytes() == before
    assert not log_path(tmp_path).exists()


def test_without_a_saved_copy_there_is_nothing_to_compare(tmp_path, capsys):
    asker = Asker("yes", "Fares")
    assert accept(tmp_path, FakeNet(), asker) == 1
    assert "cra run" in capsys.readouterr().out
    assert asker.questions == []
    assert not saved_path(tmp_path).exists() and not log_path(tmp_path).exists()


def test_the_other_kev_checks_still_apply_a_big_drop_is_refused(tmp_path, capsys):
    seed(tmp_path)
    before = saved_path(tmp_path).read_bytes()
    many = [e["cveID"] for e in REAL_KEV["vulnerabilities"][:200]]  # about 11%: more than the 5% allowed
    asker = Asker("yes", "Fares")
    assert accept(tmp_path, net_without(*many), asker) == 1
    assert "5%" in capsys.readouterr().out
    assert asker.questions == []
    assert saved_path(tmp_path).read_bytes() == before


def test_the_other_kev_checks_still_apply_a_future_date_is_refused(tmp_path, capsys):
    seed(tmp_path)
    before = saved_path(tmp_path).read_bytes()
    future = _kev_without(*GONE)
    future["dateReleased"] = (NOW + timedelta(days=400)).isoformat()
    asker = Asker("yes", "Fares")
    assert accept(tmp_path, FakeNet(kev=json.dumps(future).encode()), asker) == 1
    assert "future" in capsys.readouterr().out
    assert asker.questions == []
    assert saved_path(tmp_path).read_bytes() == before


def test_the_other_kev_checks_still_apply_an_older_list_is_refused(tmp_path, capsys):
    seed(tmp_path)
    before = saved_path(tmp_path).read_bytes()
    older = _kev_without(*GONE)
    older["dateReleased"] = (NOW - timedelta(days=30)).isoformat()
    assert accept(tmp_path, FakeNet(kev=json.dumps(older).encode()), Asker("yes", "Fares")) == 1
    assert "replay" in capsys.readouterr().out
    assert saved_path(tmp_path).read_bytes() == before


@pytest.mark.parametrize("flag", ["--yes", "-y", "--force", "--assume-yes"])
def test_there_is_no_flag_that_skips_the_question(tmp_path, flag):
    seed(tmp_path)
    before = saved_path(tmp_path).read_bytes()
    with pytest.raises(SystemExit) as stop:
        main(["kev", "accept-removals", flag, "--cache", str(tmp_path)], fetch=net_without(*GONE),
             sleep=no_sleep, now=now, ask=Asker("yes", "Fares"))
    assert stop.value.code == 2
    assert saved_path(tmp_path).read_bytes() == before


def test_piped_input_does_not_count_as_a_human(tmp_path, monkeypatch, capsys):
    seed(tmp_path)
    before = saved_path(tmp_path).read_bytes()
    monkeypatch.setattr("sys.stdin", io.StringIO("yes\nFares\n"))  # not a keyboard: isatty() is False
    code = main(["kev", "accept-removals", "--cache", str(tmp_path)], fetch=net_without(*GONE),
                sleep=no_sleep, now=now)
    assert code == 1
    assert "cancel" in capsys.readouterr().out.lower()
    assert saved_path(tmp_path).read_bytes() == before
    assert not log_path(tmp_path).exists()


def test_cra_run_never_accepts_removals_by_itself(tmp_path):
    seed(tmp_path)
    before = saved_path(tmp_path).read_bytes()
    _, status = nw.fetch_kev(tmp_path, net_without(*GONE), no_sleep, now)
    assert status["status"] == "stale"
    assert saved_path(tmp_path).read_bytes() == before
    assert not log_path(tmp_path).exists()


def test_if_the_log_cannot_be_written_the_saved_copy_is_not_replaced(tmp_path, capsys):
    seed(tmp_path)
    before = saved_path(tmp_path).read_bytes()
    log_path(tmp_path).mkdir()  # a folder where the log file should be: appending fails
    assert accept(tmp_path, net_without(*GONE), Asker("yes", "Fares")) == 1
    assert "not changed" in capsys.readouterr().out.lower()
    assert saved_path(tmp_path).read_bytes() == before


def test_a_newer_saved_copy_made_while_the_human_decides_is_not_rolled_back(tmp_path, capsys):
    seed(tmp_path)

    import copy
    answers = iter(["yes", "Fares"])

    def ask(question):
        # meanwhile a normal run saves a newer list that only adds an id
        newer = copy.deepcopy(REAL_KEV)
        newer["dateReleased"] = (NOW - timedelta(minutes=5)).isoformat()
        newer["vulnerabilities"].append({"cveID": "CVE-2099-00010", "dateAdded": "2024-01-01"})
        newer["count"] = len(newer["vulnerabilities"])
        nw.fetch_kev(tmp_path, FakeNet(kev=json.dumps(newer).encode()), no_sleep, lambda: NOW + timedelta(minutes=1))
        return next(answers)

    assert accept(tmp_path, net_without(*GONE), ask) == 1
    assert "changed while you were deciding" in capsys.readouterr().out
    saved = json.loads(saved_path(tmp_path).read_text(encoding="utf-8"))
    assert "CVE-2099-00010" in nw.kev_cve_ids(saved["data"])  # the newer list is still there
    assert not log_path(tmp_path).exists()


def test_the_screen_shows_counts_and_release_dates(tmp_path, capsys):
    seed(tmp_path)
    accept(tmp_path, net_without(*GONE), Asker("no"))
    out = capsys.readouterr().out
    assert f"{REAL_KEV['count']} entries" in out and f"{REAL_KEV['count'] - 2} entries" in out
    assert REAL_KEV["dateReleased"] in out
