"""Q1 piece 4: `alerts --test` shows one fixed test notification, `alerts --list` shows the last alerts from the log."""

import pytest

from src import alerts
from src.cli import main
from tests.test_alerts_rules import FakeNotifier, NOW

NOTHING = dict(fetch=None, sleep=None)


def alerts_cmd(tmp_path, *flags, notify=None, now=NOW):
    return main(["alerts", *flags, "--cache", str(tmp_path / "cache")], now=lambda: now, notify=notify)


def test_test_shows_one_fixed_notification_and_says_so(tmp_path, capsys):
    notifier = FakeNotifier()
    assert alerts_cmd(tmp_path, "--test", notify=notifier) == 0
    assert notifier.calls == [(alerts.TITLE, "Test notification. If you can read this, alerts work on this computer.")]
    out = capsys.readouterr().out
    assert "test notification" in out.lower() and "did you see it" in out.lower()


def test_test_that_cannot_show_says_so_and_exits_1_and_logs_it(tmp_path, capsys):
    assert alerts_cmd(tmp_path, "--test", notify=FakeNotifier(shown=False)) == 1
    out = capsys.readouterr().out
    assert "NOT shown" in out and "alerts.log" in out
    assert "TEST" in (tmp_path / "cache" / "alerts.log").read_text(encoding="utf-8")


def test_test_does_not_touch_the_alert_memory(tmp_path):
    alerts_cmd(tmp_path, "--test", notify=FakeNotifier())
    assert not (tmp_path / "cache" / "alerts-state.json").exists()


def test_a_notifier_that_raises_is_handled(tmp_path):
    assert alerts_cmd(tmp_path, "--test", notify=FakeNotifier(shown=RuntimeError("x"))) == 1


def test_list_without_a_log_says_no_alerts_yet(tmp_path, capsys):
    assert alerts_cmd(tmp_path, "--list") == 0
    assert "No alerts" in capsys.readouterr().out


def test_list_shows_the_last_lines_newest_last(tmp_path, capsys):
    from datetime import timedelta
    for i in range(30):
        alerts.append_log(tmp_path / "cache", NOW + timedelta(minutes=i), alerts.RUN_FAILED, [], True)
    assert alerts_cmd(tmp_path, "--list") == 0
    lines = [l for l in capsys.readouterr().out.splitlines() if "RUN_FAILED" in l]
    assert len(lines) == alerts.LIST_LINES and lines[-1].strip().startswith("2026-10-21T12:29:00Z")


def test_list_never_shows_control_characters_from_a_tampered_log(tmp_path, capsys):
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / "alerts.log").write_bytes(b"ok line\n\x1b[31mred\x1b[0m \x07 evil\n")
    alerts_cmd(tmp_path, "--list")
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out and "evil" in out


def test_list_reads_only_the_end_of_a_huge_log(tmp_path, capsys):
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / "alerts.log").write_bytes(b"x" * (alerts.MAX_LIST_BYTES * 5) + b"\nlast line\n")
    assert alerts_cmd(tmp_path, "--list") == 0
    out = capsys.readouterr().out
    assert "last line" in out and len(out) < alerts.MAX_LIST_BYTES + 2000


def test_list_when_the_log_is_a_folder_does_not_crash(tmp_path, capsys):
    (tmp_path / "cache" / "alerts.log").mkdir(parents=True)
    assert alerts_cmd(tmp_path, "--list") == 1
    assert "could not be read" in capsys.readouterr().out


def test_one_of_the_two_flags_is_required_and_they_exclude_each_other(tmp_path):
    with pytest.raises(SystemExit):
        alerts_cmd(tmp_path)
    with pytest.raises(SystemExit):
        alerts_cmd(tmp_path, "--test", "--list")


def test_the_help_text_names_both_flags(capsys):
    with pytest.raises(SystemExit):
        main(["alerts", "--help"])
    out = capsys.readouterr().out
    assert "--test" in out and "--list" in out


def test_list_never_shows_a_cut_off_first_line(tmp_path, capsys):
    (tmp_path / "cache").mkdir()
    # 'ä' is 2 bytes; the 64 KB window will start in the middle of the long first line
    (tmp_path / "cache" / "alerts.log").write_bytes(("ä" * 60000 + "\nreal line one\nreal line two\n").encode("utf-8"))
    assert alerts_cmd(tmp_path, "--list") == 0
    out = capsys.readouterr().out
    assert "real line one" in out and "real line two" in out
    assert "ä" not in out and "�" not in out


def test_list_shows_no_fragment_of_a_huge_single_line(tmp_path, capsys):
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / "alerts.log").write_bytes(b"x" * (alerts.MAX_LIST_BYTES * 5) + b"\nlast line\n")
    alerts_cmd(tmp_path, "--list")
    assert "xxxx" not in capsys.readouterr().out


def test_list_hides_more_unusual_control_and_direction_characters(tmp_path, capsys):
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / "alerts.log").write_text("a\u009bb ‮ c d \u0085 e\n", encoding="utf-8")
    alerts_cmd(tmp_path, "--list")
    out = capsys.readouterr().out
    for bad in ("\u009b", "‮", " ", "\u0085"):
        assert bad not in out


def test_test_without_an_injected_notifier_uses_the_safe_default(tmp_path, _no_real_notifications):
    assert alerts_cmd(tmp_path, "--test") == 0
    assert len(_no_real_notifications.calls) == 1
