"""The `cra` command-line tool.

Run it with:  python -m src <command>   (from the project folder, using the .venv python)

Commands:
    check-sbom   read an SBOM and list its components
    run          download the public data, check the product, save the run in runs/
    status       show when the last successful run was, with loud warnings

Exit codes of `run`:
    0 = complete result, nothing exploited and affected found
    1 = RESULT INCOMPLETE or something needs a human look (unknown / affected but not exploited)
    2 = input rejected
    3 = at least one REPORT CASE (an affected component with an actively exploited vulnerability)
Exit codes of `check-sbom`: 0 = all fine, 1 = RESULT INCOMPLETE (UNKNOWN component or warning), 2 = rejected.

The tool NEVER sends anything. A human always decides (CLAUDE.md rule 6).
"""

import argparse
import sys

from src import matcher, news_watcher
from src.sbom_reader import ConfigError, SbomError, load_sbom, read_product_config

KEV_NOTE = "Note: KEV is a floor, not a ceiling. It can lag behind and is US-focused; other sources still matter."


def _check_sbom(args):
    try:
        config = read_product_config(args.config) if args.config else None
        result = load_sbom(args.sbom)
    except (ConfigError, SbomError) as error:
        print(f"REJECTED: {error}", file=sys.stderr)
        return 2

    if config:
        print(f"Product: {config['product_name']} ({config['manufacturer']})")
        print(f"Member states: {', '.join(config['member_states'])}")
    print(f"Components found: {len(result.components)}")
    for component in result.components:
        label = f"{component.name or '(unnamed)'} {component.version or '?'}"
        if component.status == "OK":
            print(f"  OK       {label}  [{component.ecosystem}]")
        else:
            print(f"  UNKNOWN  {label}  - {component.reason}")
    for warning in result.warnings:
        print(f"WARNING: {warning}")
    unknown = sum(1 for c in result.components if c.status != "OK")
    if unknown:
        print(f"{unknown} component(s) are UNKNOWN: they could not be checked and need a human.")
    if unknown or result.warnings:
        print("RESULT INCOMPLETE - do not rely on this SBOM check as an all-clear.")
        return 1
    return 0


def _describe(finding):
    name = finding["component"] or "(unnamed)"
    version = finding["version"] or "?"
    vuln = finding["vulnerability_id"] or "-"
    cves = ", ".join(finding["cve_ids"]) or "no CVE id"
    text = f"{name} {version}: {vuln} ({cves}) -> {finding['status']} [{finding['rule']}]"
    if finding["exploited"]:
        text += f" - ACTIVELY EXPLOITED per {finding['exploited_via']} ({finding['exploited_cve']})"
        if finding["exploited_cve_matched_on"] != "id":
            text += f", linked through an {finding['exploited_cve_matched_on']}: a human should confirm"
    elif not finding["exploited_known"]:
        text += " - could NOT check if it is exploited (KEV list not fresh)"
    return text


def _run(args):
    try:
        config = read_product_config(args.config)
        sbom = load_sbom(args.sbom)
    except (ConfigError, SbomError) as error:
        print(f"REJECTED: {error}", file=sys.stderr)
        return 2

    started = args.now()
    try:
        feeds = news_watcher.collect(sbom.components, args.cache, args.fetch, args.sleep, args.now)
        result = matcher.evaluate(sbom.components, feeds, args.evidence)
    except OSError as error:
        print(f"RESULT INCOMPLETE - the cache folder could not be used ({type(error).__name__}).")
        print("Nothing was sent. A human decides what happens next.")
        return 1
    except Exception as error:  # a last safety net: never end with a raw traceback and a wrong exit code
        print(f"RESULT INCOMPLETE - internal error ({type(error).__name__}). Do not rely on this run.")
        print("Nothing was sent. A human decides what happens next.")
        return 1
    finished = args.now()

    print(f"Product: {config['product_name']} ({config['manufacturer']})  Member states: {', '.join(config['member_states'])}")
    for name, source in (("KEV", feeds.kev_status), ("OSV", feeds.osv_status)):
        print(f"Source {name}: {source.get('status')} - {source.get('detail')}")
    print(f"Components checked: {feeds.checked}, not checkable (UNKNOWN): {feeds.unchecked}")

    findings = result["findings"]
    by_action = {}
    for finding in findings:
        by_action.setdefault(finding["action"], []).append(finding)
    for action, title in (
        ("REPORT_CASE", "REPORT CASE (affected AND actively exploited - the 24-hour clock may be running)"),
        ("URGENT_HUMAN_REVIEW", "URGENT HUMAN REVIEW"),
        ("HUMAN_REVIEW", "Human review"),
        ("RECORD", "Recorded (affected, not known to be exploited)"),
    ):
        for finding in by_action.get(action, []):
            print(f"[{title}] {_describe(finding)}")
    if result["ignored_withdrawn"]:
        print(f"Ignored withdrawn advisories: {result['ignored_withdrawn']}")
    for warning in sbom.warnings:
        print(f"WARNING: {warning}")

    complete = feeds.complete and not sbom.warnings
    report_cases = by_action.get("REPORT_CASE", [])
    needs_human = any(f["action"] != "NONE" for f in findings)

    run = {
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "complete": complete,
        "report_cases": len(report_cases),
        "needs_human": needs_human,
        "product": config,
        "sources": {"kev": feeds.kev_status, "osv": feeds.osv_status},
        "components": {"checked": feeds.checked, "unchecked": feeds.unchecked},
        "sbom_warnings": sbom.warnings,
        "result": result,
    }
    saved_path = None
    try:
        saved_path = news_watcher.save_run(args.runs, run, args.now)
    except OSError as error:
        complete = False
        print(f"RUN NOT SAVED ({type(error).__name__}): `cra status` will not see this run.")

    if not complete:
        print("RESULT INCOMPLETE - do not rely on this. Some source or component could not be fully checked.")
    elif not report_cases and not needs_human:
        print("No exploited vulnerabilities found in the checked components (all sources ok).")
    print(KEV_NOTE)
    if saved_path:
        print(f"Run saved: {saved_path}")
    print("Nothing was sent. A human decides what happens next.")

    if report_cases:
        return 3
    return 0 if complete and not needs_human else 1


def _status(args):
    lines, ok = news_watcher.status_summary(args.runs, args.now)
    for line in lines:
        print(line)
    return 0 if ok else 1


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cra", description="CRA Copilot: helps with the CRA 24-hour early warning. Never sends anything."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check-sbom", help="read an SBOM and list its components")
    check.add_argument("sbom", help="path to a CycloneDX JSON file")
    check.add_argument("--config", help="path to the product config JSON file")
    check.set_defaults(handler=_check_sbom)

    run = commands.add_parser("run", help="download public data and check the product")
    run.add_argument("--sbom", required=True, help="path to a CycloneDX JSON file")
    run.add_argument("--config", required=True, help="path to the product config JSON file")
    run.add_argument("--cache", default="cache", help="folder for saved downloads (default: cache)")
    run.add_argument("--runs", default="runs", help="folder for run records (default: runs)")
    run.add_argument("--evidence", default="evidence", help="folder with human evidence files (default: evidence)")
    run.set_defaults(handler=_run)

    status = commands.add_parser("status", help="show the state of the last runs")
    status.add_argument("--runs", default="runs", help="folder for run records (default: runs)")
    status.set_defaults(handler=_status)
    return parser


def main(argv=None, fetch=None, sleep=None, now=None):
    """`fetch`, `sleep` and `now` can be replaced by tests; normal use leaves them empty."""
    # A Windows console may not be able to show every character: never crash because of that.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    args.fetch = fetch or news_watcher.http_fetch
    args.sleep = sleep or news_watcher.time.sleep
    args.now = now or news_watcher.utc_now
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
