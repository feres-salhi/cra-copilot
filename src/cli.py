"""The `cra` command-line tool.

Run it with:  python -m src <command>   (from the project folder, using the .venv python)

Commands:
    check-sbom   read an SBOM and list its components
    run          download the public data, check the product, save the run in runs/
    status       show when the last successful run was, with loud warnings
    approve      a human reads and approves a PENDING case (asks questions; nothing is sent)
    draft        create a PENDING case from a possible report case (a human types the awareness time)
    preview-report   print the German + English draft of each possible report case of a saved run (saves and sends nothing)
    kev accept-removals   a human accepts a KEV list that lost CVE ids (types "yes" and a name; nothing skips this)

Exit codes of `run`:
    0 = complete result, nothing exploited and affected found
    1 = RESULT INCOMPLETE or something needs a human look (unknown / affected but not exploited)
    2 = input rejected
    3 = at least one POSSIBLE REPORT CASE (an affected component with an actively exploited vulnerability)
Exit codes of `check-sbom`: 0 = all fine, 1 = RESULT INCOMPLETE (UNKNOWN component or warning), 2 = rejected.

The tool NEVER sends anything. A human always decides (CLAUDE.md rule 6).
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

from src import case_commands, matcher, news_watcher, report_facts, report_writer
from src.sbom_reader import ConfigError, SbomError, load_sbom, read_product_config

# Default folders are fixed next to the program, not "wherever the command was started":
# the Windows Task Scheduler starts programs in other folders, and `run` and `status` must see the same files.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

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
        if finding.get("evidence"):
            text += f" [evidence: {finding['evidence']['source_url']}, dated {finding['evidence']['date']}]"
        if finding["exploited_cve_matched_on"] != "id":
            text += f", linked through an {finding['exploited_cve_matched_on']}: a human should confirm"
    elif finding.get("evidence_problem"):
        text += f" - a human evidence file for {', '.join(finding['evidence_problem'])} exists but is UNUSABLE: fix it"
    elif not finding["exploited_known"]:
        text += " - could NOT check if it is exploited (no fresh KEV list or no vulnerability list to compare)"
    return text


def _save_failed_run(args, started, error_name):
    """A crashed run must still leave a record, so `status` does not keep showing an older good run."""
    record = {
        "started_at": started.isoformat(),
        "finished_at": args.now().isoformat(),
        "complete": False,
        "error": error_name,
        "sources": {},
        "components": {},
    }
    try:
        news_watcher.save_run(args.runs, record, args.now)
        print("A record of this failed run was saved; `cra status` will show it.")
    except OSError:
        print("The record of this failed run could NOT be saved either.")


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
        _save_failed_run(args, started, type(error).__name__)
        print("Nothing was sent. A human decides what happens next.")
        return 1
    except Exception as error:  # a last safety net: never end with a raw traceback and a wrong exit code
        print(f"RESULT INCOMPLETE - internal error ({type(error).__name__}). Do not rely on this run.")
        _save_failed_run(args, started, type(error).__name__)
        print("Nothing was sent. A human decides what happens next.")
        return 1
    finished = args.now()
    evidence_folder_exists = Path(args.evidence).is_dir()
    try:
        sbom_sha256 = hashlib.sha256(Path(args.sbom).read_bytes()).hexdigest()
    except OSError:
        sbom_sha256 = None

    print(f"Product: {config['product_name']} ({config['manufacturer']})  Member states: {', '.join(config['member_states'])}")
    for name, source in (("KEV", feeds.kev_status), ("OSV", feeds.osv_status)):
        print(f"Source {name}: {source.get('status')} - {source.get('detail')}")
    print(f"Components checked: {feeds.checked}, not checkable (UNKNOWN): {feeds.unchecked}")
    print(f"Folders: cache={news_watcher.printable(str(args.cache))}  runs={news_watcher.printable(str(args.runs))}  "
          f"evidence={news_watcher.printable(str(args.evidence))}")
    if not evidence_folder_exists:
        print("Note: the evidence folder does not exist, so no human evidence was used.")

    findings = result["findings"]
    by_action = {}
    for finding in findings:
        by_action.setdefault(finding["action"], []).append(finding)
    if by_action.get("REPORT_CASE"):
        print("Check the 24-hour deadline: the clock may be running (it starts when your company becomes aware).")
    for action, title in (
        ("REPORT_CASE", matcher.REPORT_CASE_LABEL),
        ("URGENT_HUMAN_REVIEW", "URGENT HUMAN REVIEW"),
        ("HUMAN_REVIEW", "Human review"),
        ("RECORD", "Recorded (affected, not known to be exploited)"),
    ):
        for finding in by_action.get(action, []):
            print(f"[{title}] {_describe(finding)}")
    if result["packages"]:
        print("Per package (if any version of a package is AFFECTED, the package counts as AFFECTED):")
        for package, package_status in sorted(result["packages"].items()):
            print(f"  {package}: {package_status}")
    if result["ignored_withdrawn"]:
        print(f"Ignored withdrawn advisories: {result['ignored_withdrawn']}")
    for warning in sbom.warnings:
        print(f"WARNING: {warning}")

    complete = feeds.complete and not sbom.warnings and result["data_gaps"] == 0
    if result["data_gaps"]:
        print(f"WARNING: {result['data_gaps']} finding(s) could not be judged because data was missing, cut off or unreadable.")
    report_cases = by_action.get("REPORT_CASE", [])
    needs_human = any(f["action"] != "NONE" for f in findings)

    run = {
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "complete": complete,
        "report_cases": len(report_cases),
        "needs_human": needs_human,
        "product": config,
        "sbom_sha256": sbom_sha256,
        "folders": {"cache": str(args.cache), "runs": str(args.runs), "evidence": str(args.evidence),
                    "evidence_folder_exists": evidence_folder_exists},
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


def ask_human(question):
    """Ask a question on the keyboard. Piped input or a scheduled task is not a human: it cancels."""
    if not sys.stdin or not sys.stdin.isatty():
        raise EOFError("no keyboard attached")
    return input(question)


def _kev_accept_removals(args):
    """Decision S2: a human may accept a KEV list that lost CVE ids. Never runs by itself, no flag skips the question."""
    try:
        check = news_watcher.check_kev_removals(args.cache, args.fetch, args.sleep, args.now)
    except news_watcher.FetchError as error:
        print(f"Nothing changed. KEV download failed or the list was refused: {error}")
        if "dropped by more than 5%" in str(error):
            print("This command cannot accept a drop of more than 5%. If CISA really removed that many, a human must "
                  "check it and then delete cache/kev/kev-saved.json by hand.")
        return 1
    except OSError as error:
        print(f"Nothing changed. The cache folder could not be used ({type(error).__name__}).")
        return 1
    if not check.removed:
        print("No CVE id disappeared from the KEV list. Nothing to accept, nothing changed.")
        return 0

    print(f"The new KEV list no longer contains {len(check.removed)} CVE id(s) that the saved copy has:")
    for cve in check.removed:
        print(f"  {cve}")
    print(f"Saved copy: {check.saved_count} entries, released {check.saved_released}. "
          f"New list: {len(check.data['vulnerabilities'])} entries, released {check.data['dateReleased']}.")
    print("Check on the CISA website that CISA removed them on purpose before you accept.")
    try:
        if args.ask('Type the word "yes" to accept these removals: ').strip() != "yes":
            print("Cancelled. Nothing changed.")
            return 1
        name = news_watcher.clean_human_name(args.ask("Type your name (it is written to the log): "))
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled. Nothing changed.")
        return 1
    if name is None:
        print("Cancelled (the name is empty, too long or has special characters). Nothing changed.")
        return 1
    try:
        news_watcher.accept_kev_removals(args.cache, check, name, args.now)
    except news_watcher.KevCopyChanged:
        print("The saved KEV copy changed while you were deciding (for example a `cra run` saved a newer list). "
              "Nothing was changed. Run this command again.")
        return 1
    except OSError as error:
        print(f"The saved KEV copy was NOT changed: the decision could not be saved ({type(error).__name__}).")
        return 1
    print(f"Accepted. The saved KEV copy was replaced; {len(check.removed)} removed id(s) were logged in "
          "cache/kev/accepted-removals.log.")
    return 0


PREVIEW_BANNER = "PREVIEW - NOT A REPORT, NOTHING IS SENT"
MAX_PREVIEW_CASES = 50  # a forged run file must not cause an endless number of AI calls


def _load_sealed_run(path):
    """The saved run record as a dict, or (None, reason). A record without a valid seal is not trusted."""
    return news_watcher.read_sealed_run(path)


def _say(text, limit=1500):
    """Print text line by line through the terminal-safe printer (defence in depth: control characters become '?')."""
    for line in str(text).split("\n"):
        print(news_watcher.printable(line, limit))


def _print_notes(run, args):
    """Honest notes about what the preview did NOT check. Returns the set of CVE ids of the saved KEV list (or None)."""
    print("Note: this preview trusts the saved run record. A human must confirm that the component really is part of the "
          "product (the 'affected' result is not checked against the SBOM again here).")
    if not news_watcher.run_is_complete(run):
        print("Note: this run was INCOMPLETE (a source or a component could not be fully checked), so more cases may exist.")
    saved_kev, kev_meta = news_watcher.load_kev_cache(args.cache, args.now)
    if saved_kev is None:
        print("Note: no usable saved KEV list was found, so no KEV-based case can be verified.")
        return None
    used = (run.get("sources") or {}).get("kev") if isinstance(run.get("sources"), dict) else None
    used_sha = used.get("sha256") if isinstance(used, dict) else None
    if used_sha and kev_meta and kev_meta.get("sha256") != used_sha:
        print("Note: the saved KEV list is not the one this run used (it was updated since); cases are checked against the newer list.")
    return news_watcher.kev_cve_ids(saved_kev)


def _print_draft(facts, draft):
    """Print one case. Returns the number of name fields that contain a claim word."""
    print(f"\n=== {matcher.REPORT_CASE_LABEL}: {facts['cve_id']} in {facts['component']} {facts['version']} ===")
    if draft.source["mode"] == "ai":
        print("Summary written by: AI (checked by code)")
    else:
        print(f"Summary written by: fixed fallback text ({news_watcher.printable(draft.source['reason'], 300)})")
    suspicious = report_facts.claim_word_warnings(facts)
    if suspicious:
        print(f"WARNING: {', '.join(suspicious)} contain(s) a word that reads like a statement (approved, sent, safe, fixed ...). "
              "Check the wording of these names.")
    if draft.reports:
        print(f"\n--- ENGLISH --- ({PREVIEW_BANNER})")
        _say(draft.reports["en"].rstrip("\n"))
        print(f"\n--- DEUTSCH --- ({PREVIEW_BANNER})")
        _say(draft.reports["de"].rstrip("\n"))
    print(f"\nFact check: {draft.check.status}")
    for item in draft.check.problems:
        print(f"  - {news_watcher.printable(item, 300)}")
    return len(suspicious)


def _preview_report(args):
    """Phase 3: show the draft of every possible report case in a saved run. Saves nothing, sends nothing."""
    print(PREVIEW_BANNER)
    code = _preview_body(args)
    print(PREVIEW_BANNER)
    return code


def _preview_body(args):
    """0 = no case, or every shown case passed; 1 = a case cannot be shown or a check failed; 2 = input rejected."""
    run, problem = _load_sealed_run(args.run)
    if run is None:
        print(f"REJECTED: {problem}.")
        return 2

    ai = None
    if args.live_ai:
        try:
            ai = args.ai or report_writer.make_gemini_ai(args.env_file)
        except report_writer.AiNotConfigured as error:
            print(f"The AI is not configured: {error}")
            return 2

    result = run.get("result") if isinstance(run.get("result"), dict) else {}
    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    cases = [f for f in findings if isinstance(f, dict) and f.get("action") == "REPORT_CASE"]
    kev_ids = _print_notes(run, args)
    if not cases:
        print("No POSSIBLE REPORT CASE in this run.")
        return 0

    all_ok = True
    seen = set()
    shown = folded = skipped = warnings = 0
    for finding in cases:
        name = f"{news_watcher.printable(finding.get('component'), 60)} / {news_watcher.printable(finding.get('exploited_cve'), 30)}"
        try:
            facts = report_facts.build_facts(run.get("product"), finding, kev_ids=kev_ids, evidence_dir=args.evidence)
        except report_facts.FactsError as error:
            all_ok = False
            print(f"\nA possible report case in this run cannot be shown ({name}): cannot build the facts ({news_watcher.printable(str(error))}).")
            continue
        key = json.dumps(facts, sort_keys=True)
        if key in seen:  # several advisories can lead to the same component and CVE
            folded += 1
            continue
        if shown >= MAX_PREVIEW_CASES:
            skipped += 1
            continue
        seen.add(key)
        shown += 1
        if args.live_ai and shown == 1:
            print("\nCalling Google Gemini with fixed prompts only (no product data is sent).")
        try:
            draft = report_writer.build_draft(facts, ai)
        except Exception as error:  # never end with a traceback
            all_ok = False
            print(f"\nThe draft for {name} could not be written ({type(error).__name__}).")
            continue
        warnings += _print_draft(facts, draft)
        all_ok = all_ok and draft.check.status == "PASS"
    if folded:
        print(f"\n{folded} more advisory entr{'y' if folded == 1 else 'ies'} lead to a case that is shown above (not repeated).")
    if skipped:
        print(f"\n{skipped} further case(s) were not shown (limit: {MAX_PREVIEW_CASES}).")
        all_ok = False
    if warnings:
        print(f"\nWARNING: {warnings} name field(s) contain a word that reads like a statement. Check the wording before relying on a draft.")
    closing = f"{shown} case(s) shown. Nothing was saved. Nothing was sent. A human decides what happens next."
    print("\n" + closing + (" (WARNING: check the wording of the names above.)" if warnings else ""))
    return 0 if all_ok else 1


def _cve_argument(text):
    if not matcher.CVE_PATTERN.fullmatch(text):
        raise argparse.ArgumentTypeError("a CVE id looks like CVE-2021-44228")
    return text


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
    run.add_argument("--cache", default=str(PROJECT_ROOT / "cache"), help="folder for saved downloads")
    run.add_argument("--runs", default=str(PROJECT_ROOT / "runs"), help="folder for run records")
    run.add_argument("--evidence", default=str(PROJECT_ROOT / "evidence"), help="folder with human evidence files")
    run.set_defaults(handler=_run)

    status = commands.add_parser("status", help="show the state of the last runs")
    status.add_argument("--runs", default=str(PROJECT_ROOT / "runs"), help="folder for run records")
    status.set_defaults(handler=_status)

    preview = commands.add_parser(
        "preview-report", help="print the German + English draft of each possible report case of a run (saves and sends nothing)")
    preview.add_argument("--run", required=True, help="path to a saved run record (a file in runs/)")
    preview.add_argument("--cache", default=str(PROJECT_ROOT / "cache"), help="folder with the saved KEV list")
    preview.add_argument("--evidence", default=str(PROJECT_ROOT / "evidence"), help="folder with human evidence files")
    preview.add_argument("--env-file", default=str(PROJECT_ROOT / ".env"), help="file with GEMINI_API_KEY (only read with --live-ai)")
    preview.add_argument("--live-ai", action="store_true", help="let Google Gemini write the summary paragraph (default: off)")
    preview.set_defaults(handler=_preview_report)

    draft = commands.add_parser(
        "draft", help="create a PENDING case from a possible report case of a run (you type the awareness time; nothing is sent)")
    draft.add_argument("--run", required=True, help="path to a saved run record (a file in runs/)")
    draft.add_argument("--sbom", required=True, help="path to the CycloneDX JSON file the run used (checked again)")
    draft.add_argument("--config", required=True, help="path to the product config JSON file the run used")
    draft.add_argument("--cve", type=_cve_argument, help="only this CVE id (when the run has several cases)")
    draft.add_argument("--cases", default=str(PROJECT_ROOT / "cases"), help="folder for cases")
    draft.add_argument("--cache", default=str(PROJECT_ROOT / "cache"), help="folder with the saved KEV list")
    draft.add_argument("--runs", default=str(PROJECT_ROOT / "runs"), help="folder for run records")
    draft.add_argument("--evidence", default=str(PROJECT_ROOT / "evidence"), help="folder with human evidence files")
    draft.add_argument("--env-file", default=str(PROJECT_ROOT / ".env"), help="file with GEMINI_API_KEY (only read with --live-ai)")
    draft.add_argument("--live-ai", action="store_true", help="let Google Gemini write the summary paragraph (default: off)")
    draft.set_defaults(handler=case_commands.draft_command)

    approve = commands.add_parser(
        "approve", help="a human reads and approves a PENDING case (asks questions, no way around them; nothing is sent)")
    approve.add_argument("case_id", help="the case id, for example case-0123456789ab")
    approve.add_argument("--cases", default=str(PROJECT_ROOT / "cases"), help="folder for cases")
    approve.add_argument("--cache", default=str(PROJECT_ROOT / "cache"), help="folder with the saved KEV and OSV data")
    approve.add_argument("--evidence", default=str(PROJECT_ROOT / "evidence"), help="folder with human evidence files")
    approve.add_argument("--sbom", help="only if the SBOM file moved: its new path (it must still be the same file)")
    approve.add_argument("--config", help="only if the config file moved: its new path")
    approve.set_defaults(handler=case_commands.approve_command)

    kev = commands.add_parser("kev", help="work with the saved CISA KEV list")
    kev_commands = kev.add_subparsers(dest="kev_command", required=True)
    accept = kev_commands.add_parser(
        "accept-removals", help="a human accepts a KEV list that dropped CVE ids (asks first, no way around it)")
    accept.add_argument("--cache", default=str(PROJECT_ROOT / "cache"), help="folder for saved downloads")
    accept.set_defaults(handler=_kev_accept_removals)
    return parser


def main(argv=None, fetch=None, sleep=None, now=None, ask=None, ai=None):
    """`fetch`, `sleep`, `now`, `ask` and `ai` can be replaced by tests; normal use leaves them empty."""
    # A Windows console may not be able to show every character: never crash because of that.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    args.fetch = fetch or news_watcher.http_fetch
    args.sleep = sleep or news_watcher.time.sleep
    args.now = now or news_watcher.utc_now
    args.ask = ask or ask_human
    args.ai = ai
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
