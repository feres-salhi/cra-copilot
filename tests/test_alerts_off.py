"""Q1 piece 5: `run --no-alerts` turns the alerts off. Tests never show a real notification."""

from datetime import timedelta

from tests.test_alerts_rules import FakeNotifier, NOW, run_with


def test_no_alerts_means_no_notification_no_log_and_no_memory_file(tmp_path, capsys):
    notifier = FakeNotifier()
    code = run_with(tmp_path, notifier, extra=["--no-alerts"])
    out = capsys.readouterr().out
    assert code == 3  # the result of the run is the same
    assert notifier.calls == []
    assert not (tmp_path / "cache" / "alerts.log").exists()
    assert not (tmp_path / "cache" / "alerts-state.json").exists()
    assert "alerts are turned off" in out.lower()
    assert out.rstrip().endswith("Nothing was sent. A human decides what happens next.")


def test_turning_alerts_off_forgets_nothing_so_they_come_when_turned_on_again(tmp_path):
    notifier = FakeNotifier()
    run_with(tmp_path, notifier, extra=["--no-alerts"])
    run_with(tmp_path, notifier, when=NOW + timedelta(hours=4))
    assert len(notifier.calls) == 1


def test_the_default_is_alerts_on(tmp_path):
    notifier = FakeNotifier()
    run_with(tmp_path, notifier)
    assert len(notifier.calls) == 1


def test_no_alerts_also_applies_when_the_run_fails(tmp_path, monkeypatch):
    from src import news_watcher as nw
    notifier = FakeNotifier()
    monkeypatch.setattr(nw, "collect", lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
    assert run_with(tmp_path, notifier, extra=["--no-alerts"]) == 1
    assert notifier.calls == []


def test_the_help_text_names_the_option(capsys):
    import pytest
    from src.cli import main
    with pytest.raises(SystemExit):
        main(["run", "--help"])
    assert "--no-alerts" in capsys.readouterr().out


def test_no_alerts_also_applies_to_a_rejected_sbom(tmp_path):
    from src.cli import main
    from tests.test_cli_run import CONFIG
    from tests.test_news_watcher import FakeNet, no_sleep
    from tests.test_alerts_rules import NOW
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    notifier = FakeNotifier()
    args = ["run", "--sbom", str(bad), "--config", CONFIG, "--cache", str(tmp_path / "cache"), "--runs", str(tmp_path / "runs"),
            "--evidence", str(tmp_path / "evidence"), "--cases", str(tmp_path / "cases"), "--no-alerts"]
    assert main(args, fetch=FakeNet(), sleep=no_sleep, now=lambda: NOW, notify=notifier) == 2
    assert notifier.calls == []
