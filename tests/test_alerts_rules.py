"""Q1 piece 1: the alert RULES. Plain code, tested with a fake notifier (no real notification is ever shown)."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from src import alerts, cases, news_watcher as nw
from src.cli import main
from tests.test_cli_approve import approve, good_answers
from tests.test_cli_draft import GOOD_BEFORE_RUN, Keyboard, draft
from tests.test_cli_run import CONFIG, NOW, SBOM, run_cli
from tests.test_news_watcher import FakeNet, no_sleep

# the demo case made by make_case() has the effective deadline 2026-10-22 11:00 UTC
DEADLINE = datetime(2026, 10, 22, 11, 0, tzinfo=timezone.utc)


class FakeNotifier:
    def __init__(self, shown=True):
        self.shown = shown
        self.calls = []

    def __call__(self, title, body):
        self.calls.append((title, body))
        if isinstance(self.shown, Exception):
            raise self.shown
        return self.shown

    def kinds_text(self):
        return " | ".join(body for _, body in self.calls)


def run_with(tmp_path, notify, when=NOW, net=None, extra=()):
    args = ["run", "--sbom", SBOM, "--config", CONFIG, "--cache", str(tmp_path / "cache"),
            "--runs", str(tmp_path / "runs"), "--evidence", str(tmp_path / "evidence"),
            "--cases", str(tmp_path / "cases"), *extra]
    return main(args, fetch=net or FakeNet(), sleep=no_sleep, now=lambda: when, notify=notify)


def make_case(tmp_path):
    run_cli(tmp_path, extra=["--cases", str(tmp_path / "cases")])
    (run_file,) = sorted((tmp_path / "runs").glob("*.json"))
    assert draft((tmp_path, run_file), Keyboard(GOOD_BEFORE_RUN, "yes")) == 0
    (case_dir,) = (tmp_path / "cases").iterdir()
    return case_dir.name


def state_file(tmp_path):
    return tmp_path / "cache" / "alerts-state.json"


# ---------------------------------------------------------------- rule 1: a new possible report case


def test_a_new_possible_report_case_raises_one_alert_naming_the_cve(tmp_path, capsys):
    notifier = FakeNotifier()
    code = run_with(tmp_path, notifier)
    assert code == 3  # the exit code of the run is not changed by alerts
    assert len(notifier.calls) == 1
    title, body = notifier.calls[0]
    assert "CVE-2021-44228" in body and "CVE-2021-45046" in body
    assert "possible report case" in body.lower()
    assert state_file(tmp_path).is_file()


def test_the_same_case_is_not_alerted_again_in_the_next_run(tmp_path):
    notifier = FakeNotifier()
    run_with(tmp_path, notifier)
    assert len(notifier.calls) == 1
    run_with(tmp_path, notifier, when=NOW + timedelta(hours=4))
    run_with(tmp_path, notifier, when=NOW + timedelta(hours=8))
    assert len(notifier.calls) == 1


def test_only_the_case_that_was_not_alerted_before_is_alerted(tmp_path):
    notifier = FakeNotifier()
    run_with(tmp_path, notifier)
    state = json.loads(state_file(tmp_path).read_text(encoding="utf-8"))
    forgotten = next(key for key in state["alerted"] if key.startswith("report:"))
    del state["alerted"][forgotten]
    state_file(tmp_path).write_text(json.dumps(state), encoding="utf-8")
    notifier.calls.clear()
    run_with(tmp_path, notifier, when=NOW + timedelta(hours=4))
    assert len(notifier.calls) == 1
    # exactly one of the two CVEs is named
    body = notifier.calls[0][1]
    assert ("CVE-2021-44228" in body) != ("CVE-2021-45046" in body)


def test_a_run_without_anything_new_or_urgent_stays_quiet(tmp_path):
    notifier = FakeNotifier()
    net = FakeNet()
    net.batch = {}  # nothing is affected
    code = run_with(tmp_path, notifier, net=net)
    assert code in (0, 1)
    assert notifier.calls == []


# ---------------------------------------------------------------- rule 2: open cases with a near or passed deadline


def seed_report_alerts(tmp_path, when):
    """Run once so that the possible report cases count as already alerted."""
    run_with(tmp_path, FakeNotifier(), when=when)


def test_an_open_case_less_than_6_hours_before_its_deadline_alerts(tmp_path):
    case_id = make_case(tmp_path)
    seed_report_alerts(tmp_path, DEADLINE - timedelta(hours=10))
    notifier = FakeNotifier()
    run_with(tmp_path, notifier, when=DEADLINE - timedelta(hours=5))
    assert len(notifier.calls) == 1
    assert case_id in notifier.calls[0][1] and "6 hours" in notifier.calls[0][1]


def test_an_open_case_with_more_than_6_hours_left_stays_quiet(tmp_path):
    make_case(tmp_path)
    seed_report_alerts(tmp_path, DEADLINE - timedelta(hours=10))
    notifier = FakeNotifier()
    run_with(tmp_path, notifier, when=DEADLINE - timedelta(hours=7))
    assert notifier.calls == []


def test_a_passed_deadline_alerts_once_more_after_the_soon_alert(tmp_path):
    case_id = make_case(tmp_path)
    seed_report_alerts(tmp_path, DEADLINE - timedelta(hours=10))
    notifier = FakeNotifier()
    run_with(tmp_path, notifier, when=DEADLINE - timedelta(hours=5))
    run_with(tmp_path, notifier, when=DEADLINE - timedelta(hours=1))      # same stage: quiet
    run_with(tmp_path, notifier, when=DEADLINE + timedelta(hours=3))      # passed: a new alert
    run_with(tmp_path, notifier, when=DEADLINE + timedelta(hours=7))      # same stage: quiet
    assert len(notifier.calls) == 2
    assert "past" in notifier.calls[1][1].lower() and case_id in notifier.calls[1][1]


def test_an_approved_case_is_not_alerted_about_its_deadline(tmp_path):
    case_id = make_case(tmp_path)
    assert approve((tmp_path, case_id), Keyboard(*good_answers(case_id))) == 0
    seed_report_alerts(tmp_path, DEADLINE - timedelta(hours=10))
    notifier = FakeNotifier()
    run_with(tmp_path, notifier, when=DEADLINE - timedelta(hours=2))
    assert notifier.calls == []


def test_an_approved_case_that_was_changed_counts_as_open(tmp_path):
    case_id = make_case(tmp_path)
    assert approve((tmp_path, case_id), Keyboard(*good_answers(case_id))) == 0
    (tmp_path / "cases" / case_id / "approved.md").write_text("changed after approval", encoding="utf-8")
    seed_report_alerts(tmp_path, DEADLINE - timedelta(hours=10))
    notifier = FakeNotifier()
    run_with(tmp_path, notifier, when=DEADLINE - timedelta(hours=2))
    assert len(notifier.calls) == 1 and case_id in notifier.calls[0][1]


def test_a_case_folder_that_cannot_be_read_alerts(tmp_path):
    case_id = make_case(tmp_path)
    (tmp_path / "cases" / case_id / "facts.json").write_text("{ not json", encoding="utf-8")
    seed_report_alerts(tmp_path, DEADLINE - timedelta(hours=10))
    state_file(tmp_path).unlink()
    notifier = FakeNotifier()
    run_with(tmp_path, notifier, when=DEADLINE - timedelta(hours=10))
    assert any(case_id in body and "cannot be read" in body for _, body in notifier.calls)


# ---------------------------------------------------------------- rule 3: a source failed or was stale


def kev_down():
    return FakeNet(kev=nw.FetchError("HTTP 503", 503))


def test_a_failed_source_alerts_once_and_names_it(tmp_path):
    notifier = FakeNotifier()
    run_with(tmp_path, notifier, net=kev_down())
    texts = [body for _, body in notifier.calls if "source" in body.lower()]
    assert len(texts) == 1 and "KEV" in texts[0] and "failed" in texts[0]
    notifier.calls.clear()
    run_with(tmp_path, notifier, net=kev_down(), when=NOW + timedelta(hours=4))
    assert [b for _, b in notifier.calls if "source" in b.lower()] == []


def test_a_source_that_keeps_failing_reminds_after_24_hours(tmp_path):
    notifier = FakeNotifier()
    run_with(tmp_path, notifier, net=kev_down())
    notifier.calls.clear()
    run_with(tmp_path, notifier, net=kev_down(), when=NOW + timedelta(hours=25))
    assert [b for _, b in notifier.calls if "source" in b.lower()]


def test_a_source_that_recovered_and_fails_again_alerts_again(tmp_path):
    notifier = FakeNotifier()
    run_with(tmp_path, notifier, net=kev_down())
    run_with(tmp_path, notifier, when=NOW + timedelta(hours=4))   # fine again
    notifier.calls.clear()
    run_with(tmp_path, notifier, net=kev_down(), when=NOW + timedelta(hours=8))
    assert [b for _, b in notifier.calls if "source" in b.lower()]


def test_a_stale_source_is_named_as_stale(tmp_path):
    items = alerts.collect(NOW, {"manufacturer": "M", "product_name": "P"}, [], None,
                           {"status": "stale", "detail": "x"}, {"status": "ok"}, False)
    (item,) = items
    assert item.kind == alerts.SOURCE_PROBLEM and item.source == "KEV" and item.status == "stale"


def test_a_crashed_run_still_alerts_for_deadlines_and_for_the_failure(tmp_path, monkeypatch):
    case_id = make_case(tmp_path)
    seed_report_alerts(tmp_path, DEADLINE - timedelta(hours=10))
    notifier = FakeNotifier()

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(nw, "collect", boom)
    code = run_with(tmp_path, notifier, when=DEADLINE + timedelta(hours=1))
    assert code == 1
    text = notifier.kinds_text()
    assert case_id in text and "run failed" in text.lower()


# ---------------------------------------------------------------- the state file: damaged or missing means alert again


@pytest.mark.parametrize("content", ["{ not json", "[]", '{"schema": 1, "alerted": []}', '{"schema": 1, "alerted": {"a": 5}}',
                                     '{"schema": 1, "alerted": {"a": "not a time"}}', "", "￾\x00"])
def test_a_damaged_state_file_leads_to_alerting_again(tmp_path, content):
    notifier = FakeNotifier()
    run_with(tmp_path, notifier)
    assert len(notifier.calls) == 1
    state_file(tmp_path).write_text(content, encoding="utf-8")
    run_with(tmp_path, notifier, when=NOW + timedelta(hours=4))
    assert len(notifier.calls) == 2
    # and the file is healthy again afterwards
    run_with(tmp_path, notifier, when=NOW + timedelta(hours=8))
    assert len(notifier.calls) == 2


def test_a_missing_state_file_leads_to_alerting_again(tmp_path):
    notifier = FakeNotifier()
    run_with(tmp_path, notifier)
    state_file(tmp_path).unlink()
    run_with(tmp_path, notifier, when=NOW + timedelta(hours=4))
    assert len(notifier.calls) == 2


def test_a_state_file_that_is_a_folder_leads_to_alerting_again(tmp_path):
    notifier = FakeNotifier()
    (tmp_path / "cache").mkdir()
    state_file(tmp_path).mkdir()
    code = run_with(tmp_path, notifier)
    assert code == 3 and len(notifier.calls) == 1


def test_a_huge_state_file_is_treated_as_damaged(tmp_path):
    notifier = FakeNotifier()
    run_with(tmp_path, notifier)
    state_file(tmp_path).write_bytes(b" " * (alerts.MAX_STATE_BYTES + 10))
    run_with(tmp_path, notifier, when=NOW + timedelta(hours=4))
    assert len(notifier.calls) == 2


# ---------------------------------------------------------------- a notifier that fails never breaks the run, never means silence


def test_a_notifier_that_raises_does_not_crash_or_change_the_exit_code(tmp_path, capsys):
    notifier = FakeNotifier(shown=RuntimeError("boom"))
    code = run_with(tmp_path, notifier)
    assert code == 3
    assert "Nothing was sent" in capsys.readouterr().out


def test_an_alert_that_could_not_be_delivered_is_tried_again_next_run(tmp_path):
    failing = FakeNotifier(shown=False)
    run_with(tmp_path, failing)
    assert len(failing.calls) == 1
    working = FakeNotifier()
    run_with(tmp_path, working, when=NOW + timedelta(hours=4))
    assert len(working.calls) == 1


def test_the_alert_is_also_printed_in_the_run_output(tmp_path, capsys):
    run_with(tmp_path, FakeNotifier())
    out = capsys.readouterr().out
    assert "ALERT" in out and "CVE-2021-44228" in out
    assert out.rstrip().endswith("Nothing was sent. A human decides what happens next.")


def test_the_run_record_and_exit_code_are_the_same_with_and_without_a_working_notifier(tmp_path):
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    code_a = run_with(first, FakeNotifier())
    code_b = run_with(second, FakeNotifier(shown=RuntimeError("x")))
    assert code_a == code_b == 3


# ---------------------------------------------------------------- the message text: fixed wording + strict values only


def test_messages_contain_only_safe_characters():
    item_cve = alerts.Item(alerts.NEW_REPORT_CASE, "report:aaaaaaaaaaaa", cve="CVE-2021-44228", case_id="case-0123456789ab")
    title, body = alerts.build_message(alerts.NEW_REPORT_CASE, [item_cve])
    assert alerts.SAFE_TEXT.fullmatch(title) and alerts.SAFE_TEXT.fullmatch(body)
    assert "CVE-2021-44228" in body and "case-0123456789ab" in body


@pytest.mark.parametrize("evil", ["CVE-2021-1; calc.exe", "CVE-2021-44228\nGHSA", "$(calc)", "<b>x</b>", "CVE-2021-44228 ", "`x`", "'; --"])
def test_a_value_that_fails_its_pattern_never_reaches_the_text(evil):
    item = alerts.Item(alerts.NEW_REPORT_CASE, "report:aaaaaaaaaaaa", cve=evil, case_id=evil)
    title, body = alerts.build_message(alerts.NEW_REPORT_CASE, [item])
    assert evil.strip() not in body and "calc" not in body and "$" not in body and "`" not in body
    assert alerts.SAFE_TEXT.fullmatch(body)


def test_a_source_name_and_status_come_only_from_the_fixed_lists():
    items = alerts.collect(NOW, {"manufacturer": "M", "product_name": "P"}, [], None,
                           {"status": "<script>calc</script>", "detail": "evil"}, {"status": "failed", "detail": "$(x)"}, False)
    _, body = alerts.build_message(alerts.SOURCE_PROBLEM, items)
    assert "script" not in body and "calc" not in body and "$" not in body
    assert "KEV" in body and "OSV" in body and alerts.SAFE_TEXT.fullmatch(body)


def test_nothing_from_the_sbom_or_the_config_reaches_the_message(tmp_path):
    finding = {"component": "evil;calc.exe", "version": "1.0 && del *", "exploited_cve": "CVE-2021-44228"}
    items = alerts.collect(NOW, {"manufacturer": "Evil `m`", "product_name": "$(P)"}, [finding], None,
                           {"status": "ok"}, {"status": "ok"}, False)
    _, body = alerts.build_message(alerts.NEW_REPORT_CASE, items)
    for bad in ("calc", "del", "$", "`", "Evil"):
        assert bad not in body
    assert "CVE-2021-44228" in body


def test_a_long_list_is_shortened_and_still_safe():
    items = [alerts.Item(alerts.NEW_REPORT_CASE, f"report:{i:012x}", cve=f"CVE-2021-{10000 + i}", case_id=f"case-{i:012x}")
             for i in range(40)]
    _, body = alerts.build_message(alerts.NEW_REPORT_CASE, items)
    assert len(body) <= alerts.MAX_BODY and "more" in body and alerts.SAFE_TEXT.fullmatch(body)


def test_a_state_entry_dated_in_the_future_does_not_silence_an_alert(tmp_path):
    notifier = FakeNotifier()
    run_with(tmp_path, notifier)
    state = json.loads(state_file(tmp_path).read_text(encoding="utf-8"))
    state["alerted"] = {key: "2099-01-01T00:00:00+00:00" for key in state["alerted"]}
    state_file(tmp_path).write_text(json.dumps(state), encoding="utf-8")
    run_with(tmp_path, notifier, when=NOW + timedelta(hours=4))
    assert len(notifier.calls) == 2


def test_a_deadline_that_stays_passed_reminds_after_24_hours(tmp_path):
    make_case(tmp_path)
    seed_report_alerts(tmp_path, DEADLINE - timedelta(hours=10))
    notifier = FakeNotifier()
    run_with(tmp_path, notifier, when=DEADLINE + timedelta(hours=3))
    run_with(tmp_path, notifier, when=DEADLINE + timedelta(hours=20))
    assert len(notifier.calls) == 1
    run_with(tmp_path, notifier, when=DEADLINE + timedelta(hours=28))
    assert len(notifier.calls) == 2


def test_a_rejected_sbom_still_alerts_and_keeps_exit_code_2(tmp_path):
    notifier = FakeNotifier()
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    args = ["run", "--sbom", str(bad), "--config", CONFIG, "--cache", str(tmp_path / "cache"),
            "--runs", str(tmp_path / "runs"), "--evidence", str(tmp_path / "evidence"), "--cases", str(tmp_path / "cases")]
    assert main(args, fetch=FakeNet(), sleep=no_sleep, now=lambda: NOW, notify=notifier) == 2
    assert len(notifier.calls) == 1 and "run failed" in notifier.calls[0][1].lower()


def test_a_case_without_its_own_deadline_uses_the_tool_deadline(tmp_path, monkeypatch):
    case_id = make_case(tmp_path)
    loaded = cases.load_case(tmp_path / "cases", case_id)
    loaded.facts["deadline_utc"] = None
    monkeypatch.setattr(cases, "list_cases", lambda root: ([loaded], []))
    found = alerts._case_items(DEADLINE - timedelta(hours=2), tmp_path / "cases")
    assert [item.kind for item in found] == [alerts.DEADLINE_SOON]
