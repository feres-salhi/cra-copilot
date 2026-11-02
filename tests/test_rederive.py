"""Phase 4 piece 3: `cra draft` re-derives "affected" from the SBOM and the saved data instead of trusting the run record."""

import hashlib
import json
from pathlib import Path

import pytest

from src import matcher, news_watcher as nw
from src.cli import main
from src.sbom_reader import load_sbom
from tests.test_cli_draft import GOOD_BEFORE_RUN, Keyboard, LATER, draft, only_case
from tests.test_cli_run import CONFIG, NOW, SBOM, run_cli, write_sbom


@pytest.fixture
def world(tmp_path):
    run_cli(tmp_path)
    (run_file,) = (tmp_path / "runs").glob("*.json")
    return tmp_path, run_file


def forged_run(tmp_path, run_file, change):
    """A run record that carries a VALID seal (anyone can compute it) but says something that is not true."""
    run = json.loads(run_file.read_text(encoding="utf-8"))
    change(run)
    run.pop("seal", None)
    run["seal"] = nw.run_seal(run)
    path = tmp_path / "forged.json"
    path.write_text(json.dumps(run), encoding="utf-8")
    return path


def case_findings(run):
    return [f for f in run["result"]["findings"] if f["action"] == "REPORT_CASE" and f["exploited_cve"] == "CVE-2021-44228"]


def no_case_created(base):
    return not (base / "cases").exists() or list((base / "cases").iterdir()) == []


# ---------------------------------------------------------------- the offline feeds


def test_feeds_from_the_saved_cache_give_the_same_findings_as_the_run(world):
    tmp_path, run_file = world
    run = json.loads(run_file.read_text(encoding="utf-8"))
    components = load_sbom(SBOM).components
    feeds = nw.feeds_from_cache(components, tmp_path / "cache", lambda: NOW)
    result = matcher.evaluate(components, feeds, tmp_path / "evidence")
    assert result["findings"] == run["result"]["findings"]


def test_feeds_from_an_empty_cache_know_nothing_and_never_say_safe(tmp_path):
    components = load_sbom(SBOM).components
    feeds = nw.feeds_from_cache(components, tmp_path / "cache", lambda: NOW)
    assert feeds.kev is None and feeds.kev_ids == set()
    assert feeds.kev_status["status"] != "ok" and feeds.osv_status["status"] != "ok"
    assert all(v is None for v in feeds.purl_vulns.values())
    result = matcher.evaluate(components, feeds, None)
    assert not [f for f in result["findings"] if f["action"] == "REPORT_CASE"]


def test_feeds_from_cache_make_no_network_call(world, monkeypatch):
    tmp_path, _ = world

    def no_network(*args, **kwargs):
        raise AssertionError("the network must not be used")

    monkeypatch.setattr(nw, "http_fetch", no_network)
    nw.feeds_from_cache(load_sbom(SBOM).components, tmp_path / "cache", lambda: NOW)


# ---------------------------------------------------------------- cra draft with --sbom and --config


def test_draft_says_that_affected_was_derived_again_and_stores_the_sbom_fingerprint(world, capsys):
    tmp_path, _ = world
    capsys.readouterr()
    assert draft(world, Keyboard(GOOD_BEFORE_RUN, "yes")) == 0
    out = capsys.readouterr().out
    assert "Re-derived from the SBOM and the saved data: AFFECTED" in out
    origin = only_case(tmp_path).meta["origin"]
    assert origin["sbom"]["sha256"] == hashlib.sha256(Path(SBOM).read_bytes()).hexdigest()
    assert origin["sbom"]["path"] == str(Path(SBOM).resolve())
    assert origin["config_path"] == str(Path(CONFIG).resolve())
    assert origin["rederived"] is True


def test_draft_needs_the_sbom_and_the_config():
    with pytest.raises(SystemExit):
        main(["draft", "--run", "x.json"])


def test_another_sbom_than_the_one_of_the_run_is_refused(world, capsys, tmp_path):
    base, _ = world
    sbom_dir = tmp_path / "sboms"
    sbom_dir.mkdir()
    other = write_sbom(sbom_dir, ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"])
    capsys.readouterr()
    assert draft(world, Keyboard(GOOD_BEFORE_RUN, "yes"), extra=["--sbom", other]) == 1
    assert "not the SBOM this run used" in capsys.readouterr().out
    assert no_case_created(base)


def test_another_product_config_is_refused(world, capsys, tmp_path):
    base, _ = world
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"product_name": "Other Thing", "manufacturer": "Other GmbH (fictional)", "member_states": ["DE"]}),
                      encoding="utf-8")
    capsys.readouterr()
    assert draft(world, Keyboard(GOOD_BEFORE_RUN, "yes"), extra=["--config", str(config)]) == 1
    assert "not the product the run used" in capsys.readouterr().out
    assert no_case_created(base)


def test_an_unreadable_sbom_is_rejected(world, capsys, tmp_path):
    capsys.readouterr()
    assert draft(world, Keyboard(), extra=["--sbom", str(tmp_path / "missing.json")]) == 2
    assert "REJECTED" in capsys.readouterr().out


def test_a_forged_run_claiming_a_component_that_is_not_in_the_sbom_is_refused(world, capsys):
    tmp_path, run_file = world

    def change(run):
        for finding in case_findings(run):
            finding["purl"] = finding["purl"].replace("2.14.1", "2.0")
            finding["version"] = "2.0"

    path = forged_run(tmp_path, run_file, change)
    capsys.readouterr()
    assert draft(world, Keyboard(GOOD_BEFORE_RUN, "yes"), run_file=path) == 1
    assert "could not be re-derived" in capsys.readouterr().out
    assert no_case_created(tmp_path)


def test_a_forged_run_with_another_exploited_cve_is_refused(world, capsys):
    tmp_path, run_file = world

    def change(run):
        for finding in case_findings(run):
            finding["exploited_cve"] = "CVE-2022-22965"  # really in KEV, but not an advisory of this component
            finding["cve_ids"] = ["CVE-2022-22965"]

    path = forged_run(tmp_path, run_file, change)
    capsys.readouterr()
    code = main(["draft", "--run", str(path), "--cve", "CVE-2022-22965", "--sbom", SBOM, "--config", CONFIG,
                 "--cases", str(tmp_path / "cases"), "--cache", str(tmp_path / "cache"), "--runs", str(tmp_path / "runs"),
                 "--evidence", str(tmp_path / "evidence")], ask=Keyboard(GOOD_BEFORE_RUN, "yes"), now=lambda: LATER)
    assert code == 1
    assert "could not be re-derived" in capsys.readouterr().out
    assert no_case_created(tmp_path)


def test_a_forged_run_with_a_changed_product_name_is_refused(world, capsys):
    tmp_path, run_file = world

    def change(run):
        run["product"] = dict(run["product"], product_name="Totally Safe Router")

    path = forged_run(tmp_path, run_file, change)
    capsys.readouterr()
    assert draft(world, Keyboard(GOOD_BEFORE_RUN, "yes"), run_file=path) == 1
    assert "not the product the run used" in capsys.readouterr().out
    assert no_case_created(tmp_path)


def test_the_facts_come_from_the_config_not_from_the_run_record(world):
    tmp_path, _ = world
    draft(world, Keyboard(GOOD_BEFORE_RUN, "yes"))
    facts = only_case(tmp_path).facts
    config = json.loads(Path(CONFIG).read_text(encoding="utf-8"))
    assert facts["product_name"] == config["product_name"] and facts["member_states"] == config["member_states"]


def test_a_cache_that_lost_the_osv_answer_stops_the_draft(world, capsys):
    tmp_path, _ = world
    for path in (tmp_path / "cache" / "osv-query").glob("*.json"):
        path.unlink()
    capsys.readouterr()
    assert draft(world, Keyboard(GOOD_BEFORE_RUN, "yes")) == 1
    assert "could not be re-derived" in capsys.readouterr().out


def test_the_sbom_is_read_only_once_so_the_hash_and_the_parsed_components_match(world, monkeypatch):
    from src import rederive, sbom_reader
    run = json.loads(next((world[0] / "runs").glob("*.json")).read_text(encoding="utf-8"))
    calls = []
    real = sbom_reader._read_limited
    monkeypatch.setattr(sbom_reader, "_read_limited", lambda path, limit: (calls.append(path), real(path, limit))[1])
    rederive.load_inputs(SBOM, CONFIG, run["sbom_sha256"], run["product"])
    sbom_reads = [c for c in calls if str(c) == SBOM]
    assert len(sbom_reads) == 1
