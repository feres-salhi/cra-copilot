"""Phase 4: the commands that work with cases: `cra draft` (and `cra approve`).

Both are for a HUMAN at a keyboard. Piped input or a scheduled task cancels them, and there is no flag that answers a
question for the human (CLAUDE.md rule 6). Nothing here sends anything: there is no send function in this tool.
"""

import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src import awareness as aw
from src import cli_name
from src import cases, fact_checker, matcher, news_watcher, rederive, report_facts, report_template, report_writer
from src.sbom_reader import ConfigError, SbomError, read_sbom_bytes

MAX_TRIES = 3
KEV_MAX_AGE = timedelta(days=3)  # an older saved KEV list gets a warning: new entries may be missing
MAX_REASON_LENGTH = 300
MIN_REASON_LENGTH = 10
MAX_CHOICES = 50


def _ask(args, question):
    """The typed answer, or None when no human is there / the human pressed Ctrl+C or Ctrl+D."""
    try:
        return args.ask(question)
    except (EOFError, KeyboardInterrupt):
        return None


def _say(text, limit=1500):
    for line in str(text).split("\n"):
        print(news_watcher.printable(line, limit))


def _berlin_and_utc(utc_text):
    return report_facts.format_time(utc_text, "en")


def _first_found(origin):
    """(started_at, file name) of the first run that found the case, from what `cra draft` saved; (None, None) if unknown."""
    first = origin.get("first_found") if isinstance(origin, dict) else None
    try:
        started = datetime.fromisoformat(first["started_at"])
        if started.utcoffset() is None:
            return None, None
        return started.astimezone(timezone.utc), str(first["file"])
    except (KeyError, TypeError, ValueError):
        return None, None


def _tool_deadline(meta):
    """The deadline by the TOOL'S OWN clock: first run that found the case + 24 hours (None if unknown)."""
    started, _ = _first_found(meta.get("origin"))
    return started + report_facts.AWARENESS_WINDOW if started else None


def _kev_age_warning(kev_status, now):
    saved = news_watcher._parse_time(kev_status.get("downloaded_at")) if isinstance(kev_status, dict) else None
    if saved is None:
        return "WARNING: it is not known when the saved KEV list was downloaded."
    if now - saved > KEV_MAX_AGE:
        return (f"WARNING: the saved KEV list is {(now - saved).days} days old. New entries may be missing: "
                f"run `{cli_name.command('run')}` to refresh it.")
    return None


def _risky(text):
    """True for a path that is unsafe to put inside a pasted command (shell characters, or a trailing backslash)."""
    text = str(text)
    return bool(_SHELL_SPECIAL & set(text)) or text.endswith("\\")


def clean_reason(text):
    """A typed reason, or None if empty, too long or with control characters."""
    if not isinstance(text, str):
        return None
    reason = text.strip()
    if not reason or len(reason) < MIN_REASON_LENGTH or len(reason) > MAX_REASON_LENGTH or not reason.isprintable():
        return None
    return reason


# ---------------------------------------------------------------- choosing the case


def _distinct_cases(run, cve_filter):
    """The possible report cases of a run, one per (component, version, CVE)."""
    result = run.get("result") if isinstance(run.get("result"), dict) else {}
    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    seen, chosen = set(), []
    for finding in findings:
        if not isinstance(finding, dict) or finding.get("action") != "REPORT_CASE":
            continue
        if cve_filter and finding.get("exploited_cve") != cve_filter:
            continue
        key = (finding.get("component"), finding.get("version"), finding.get("exploited_cve"))
        if key not in seen:
            seen.add(key)
            chosen.append(finding)
    return chosen


def _choose(args, candidates):
    if len(candidates) == 1:
        return candidates[0]
    shown = candidates[:MAX_CHOICES]
    print(f"This run has {len(candidates)} possible report cases:")
    for number, finding in enumerate(shown, 1):
        print(f"  {number}) {news_watcher.printable(finding.get('component'), 60)} "
              f"{news_watcher.printable(finding.get('version'), 40)} - {news_watcher.printable(finding.get('exploited_cve'), 30)}")
    for _ in range(MAX_TRIES):
        answer = _ask(args, f"Which case do you want to draft? Type a number (1-{len(shown)}): ")
        if answer is None:
            return None
        if answer.strip().isascii() and answer.strip().isdigit() and 1 <= int(answer.strip()) <= len(shown):
            return shown[int(answer.strip()) - 1]
        print("That is not one of the numbers.")
    return None


# ---------------------------------------------------------------- cra draft


def draft_command(args):
    """0 = case created (or no case in the run), 1 = cancelled or refused, 2 = input rejected."""
    run, problem = news_watcher.read_sealed_run(args.run)
    if run is None:
        print(f"REJECTED: {problem}.")
        return 2
    candidates = _distinct_cases(run, args.cve)
    if not candidates:
        print("No POSSIBLE REPORT CASE in this run." if not args.cve else "No POSSIBLE REPORT CASE with that CVE in this run.")
        print(f"(`{cli_name.command('draft')}` only looks at cases the run record lists. Run `{cli_name.command('run')}` for a fresh check.)")
        return 0
    if not news_watcher.run_is_complete(run):
        print("Note: this run was INCOMPLETE (a source or a component could not be fully checked), so more cases may exist.")
    finding = _choose(args, candidates)
    if finding is None:
        print("Cancelled. Nothing was created.")
        return 1

    # The run record is only sealed with an unkeyed fingerprint: run the matcher again on the real SBOM (PLAN (i) item 3).
    try:
        config, components, sbom_sha256 = rederive.load_inputs(args.sbom, args.config, run.get("sbom_sha256"), run.get("product"))
        finding, facts, feeds = rederive.rederive(components, config, finding, args.cache, args.evidence, args.now)
    except (SbomError, ConfigError) as error:
        print(f"REJECTED: {news_watcher.printable(str(error), 300)}")
        return 2
    except rederive.RederiveError as error:
        print(f"Nothing was created: {news_watcher.printable(str(error), 400)}.")
        return 1
    age_warning = _kev_age_warning(feeds.kev_status, args.now())
    if age_warning:
        print(age_warning)
    print(f"Re-derived from the SBOM and the saved data: {finding['status']} ({finding['rule']}), the same finding as in the run record.")
    # From here on ONE copy of the saved KEV list is used: the one the matcher just used.
    kev, kev_ids, kev_meta = feeds.kev, feeds.kev_ids, feeds.kev_status
    if kev is None and facts["exploited_via"] == "kev":
        print("Nothing was created: no usable saved KEV list.")
        return 1
    case_id = cases.make_case_id(facts)
    if cases.case_path(args.cases, case_id).exists():
        print(f"Nothing was created: the case {case_id} already exists. Use `{cli_name.command('approve', case_id)}` or look at cases/{case_id}.")
        return 1

    try:
        earliest, earliest_why = aw.earliest_allowed(facts["exploited_via"], facts["cve_id"], kev, facts["evidence"]["date"])
    except aw.AwarenessError as error:
        print(f"Nothing was created: {error}.")
        return 1
    first = aw.find_first_found(args.runs, facts["product_name"], facts["component"], facts["version"], facts["cve_id"],
                                extra_run_files=[args.run])
    observation = aw.Observation(first[0] if first else None, first[1] if first else None, earliest, earliest_why)

    print(f"\n=== {matcher.REPORT_CASE_LABEL} ===")
    print(f"Product: {facts['product_name']} ({facts['manufacturer']})")
    print(f"Component: {facts['component']} {facts['version']}    Vulnerability: {facts['cve_id']} "
          f"(linked through an {facts['cve_matched_on']})")
    print(f"Runs folder searched: {news_watcher.printable(str(args.runs), 200)}")
    print("What this tool itself observed (compare it with your own knowledge):")
    if first:
        print(f"  - First run that found this case: {news_watcher.printable(first[1], 80)}, started {first[0].isoformat()}")
    else:
        print("  - First run that found this case: not found in the runs folder")
    print(f"  - Earliest awareness time the data allows: {earliest.isoformat()} ({earliest_why})")
    kev_info = None
    if facts["exploited_via"] == "kev":
        entry = next((e for e in kev["vulnerabilities"] if e.get("cveID") == facts["cve_id"]), None)
        kev_info = {"date_added": entry["dateAdded"] if entry else None, "date_released": kev.get("dateReleased"),
                    "downloaded_at": (kev_meta or {}).get("downloaded_at"), "sha256": (kev_meta or {}).get("sha256")}
        print(f"  - KEV list saved on this computer at {news_watcher.printable(kev_info['downloaded_at'], 40)}, "
              f"released {news_watcher.printable(kev_info['date_released'], 40)}, "
              f"fingerprint {news_watcher.printable(str(kev_info['sha256'])[:16], 16)}...")
        print(f"  - KEV dateAdded for {facts['cve_id']}: {kev_info['date_added']}. This tool stores no vendor or product text "
              "from KEV on purpose: compare the CVE id and this date with the CISA website by hand.")
    else:
        print(f"  - Human evidence: {facts['evidence']['url']} dated {facts['evidence']['date']}")
    print(f"The legal clock starts when YOUR company becomes aware. {aw.FORMAT_HELP}")

    awareness, reason, typed = None, None, None
    for _ in range(MAX_TRIES):
        answer = _ask(args, "When did your company become aware of this? ")
        if answer is None:
            break
        try:
            candidate = aw.parse_awareness(answer)
        except aw.AwarenessError as error:
            print(f"Not accepted: {error}")
            continue
        verdict = aw.check_awareness(candidate, args.now(), observation)
        for line in verdict.refusals:
            print(f"Not accepted: {line}")
        if verdict.refusals:
            continue
        for line in verdict.warnings:
            print(line)
        if verdict.needs_reason:
            for _ in range(MAX_TRIES):
                given = _ask(args, "Why is your awareness time later than the first run? Type a short reason (it is saved with the case): ")
                if given is None:
                    break
                reason = clean_reason(given)
                if reason:
                    break
                print(f"Not accepted: the reason must be {MIN_REASON_LENGTH} to {MAX_REASON_LENGTH} printable characters.")
            if not reason:
                break
        awareness, typed = candidate, answer.strip()
        break
    if awareness is None:
        print("Cancelled. Nothing was created.")
        return 1

    try:
        facts = report_facts.build_facts(config, finding, kev_ids=kev_ids, evidence_dir=args.evidence,
                                         awareness=awareness)
    except report_facts.FactsError as error:
        print(f"Nothing was created: {news_watcher.printable(str(error), 300)}.")
        return 1
    ai = None
    if args.live_ai:
        try:
            ai = args.ai or report_writer.make_gemini_ai(args.env_file)
        except report_writer.AiNotConfigured as error:
            print(f"The AI is not configured: {error}")
            return 2
        print("Calling Google Gemini with fixed prompts only (no product data is sent).")
    try:
        draft = report_writer.build_draft(facts, ai)
    except Exception as error:  # never end with a traceback
        print(f"Nothing was created: the draft could not be written ({type(error).__name__}).")
        return 1
    if draft.reports is None or draft.check.status != "PASS":
        print("Nothing was created: the fact check failed.")
        for item in draft.check.problems:
            print(f"  - {news_watcher.printable(item, 300)}")
        return 1

    suspicious = report_facts.claim_word_warnings(facts)
    if suspicious:
        print(f"WARNING: {', '.join(suspicious)} contain(s) a word that reads like a statement (approved, sent, safe, fixed ...). "
              "Check the wording of these names.")
    print(f"\nAwareness time: {_berlin_and_utc(facts['awareness_time_utc'])}")
    print(f"Deadline (awareness + 24 hours): {_berlin_and_utc(facts['deadline_utc'])}")
    answer = _ask(args, 'Create this case with the status PENDING? Type the word "yes": ')
    if answer is None or answer.strip() != "yes":
        print("Cancelled. Nothing was created.")
        return 1

    origin = {
        "run_file": Path(args.run).name,
        "run_seal": run.get("seal"),
        "run_started_at": run.get("started_at"),
        "first_found": {"file": first[1], "started_at": first[0].isoformat()} if first else None,
        "earliest_allowed": {"utc": earliest.isoformat(), "reason": earliest_why},
        "kev": kev_info,
        "awareness": {"typed": typed, "utc": facts["awareness_time_utc"], "reason": reason},
        "summary_mode": draft.source["mode"],
        "sbom": {"path": str(Path(args.sbom).resolve()), "sha256": sbom_sha256},
        "config_path": str(Path(args.config).resolve()),
        "rederived": True,
        "rederived_rule": finding["rule"],
    }
    try:
        created = cases.create_case(args.cases, facts, draft.reports, draft.check, draft.source,
                                    cases.new_meta(args.now(), origin))
    except cases.CaseExists:
        print("Nothing was created: this case already exists.")
        return 1
    except (cases.CaseError, OSError) as error:
        print(f"Nothing was created: {news_watcher.printable(str(error), 300)}")
        return 1
    print(f"\nCase {created} created with the status PENDING (cases/{created}/).")
    print(f"Next: read the text and approve it with:  {cli_name.command('approve', created)}")
    print("Nothing was sent. A human decides what happens next.")
    return 0


# ---------------------------------------------------------------- cra approve


def _print_case_screen(case, facts, kev_info, reports):
    print(f"\n=== {matcher.REPORT_CASE_LABEL} ===")
    print(f"Case: {case.case_id}")
    print("Please check these values against your own records:")
    for label, key in (("Manufacturer", "manufacturer"), ("Product", "product_name"), ("Component", "component"),
                       ("Component version", "version"), ("Vulnerability (CVE)", "cve_id")):
        print(f"  {label}: {news_watcher.printable(facts[key], 200)}")
    print(f"  Member states: {news_watcher.printable(', '.join(facts['member_states']), 200)}")
    print(f"  Awareness time: {_berlin_and_utc(facts['awareness_time_utc'])}")
    print(f"  Deadline (awareness + 24 hours): {_berlin_and_utc(facts['deadline_utc'])}")
    if kev_info:
        print(f"  KEV dateAdded: {kev_info['date_added']}; KEV list saved on this computer at "
              f"{news_watcher.printable(kev_info['downloaded_at'], 40)}, released {news_watcher.printable(kev_info['date_released'], 40)}. "
              "Compare the CVE id and this date with the CISA website by hand.")
    else:
        print(f"  Human evidence: {news_watcher.printable(facts['evidence']['url'], 500)} dated "
              f"{news_watcher.printable(facts['evidence']['date'], 20)}")
    print(f"\n--- ENGLISH --- (as it will be approved)")
    _say(reports["en"].rstrip("\n"))
    print(f"\n--- DEUTSCH --- (as it will be approved)")
    _say(reports["de"].rstrip("\n"))


def approve_command(args):
    """0 = approved (or already approved), 1 = refused or cancelled, 2 = the case id / case cannot be used."""
    try:
        case = cases.load_case(args.cases, args.case_id)
    except cases.CaseError as error:
        print(f"REJECTED: {news_watcher.printable(str(error), 300)}.")
        return 2
    state = cases.approval_state(case)
    if state == "APPROVED":
        print(f"The case {case.case_id} is already approved and nothing changed since. Nothing to do.")
        print("Nothing was sent. A human submits it by hand.")
        return 0
    if state == "CHANGED":
        print("WARNING: this case was approved before, but it CHANGED since it was approved. It must be approved again.")
        try:  # from now on it is PENDING and the old approved.md is gone, whatever happens next
            cases.demote_to_pending(args.cases, case.case_id)
            case = cases.load_case(args.cases, args.case_id)
        except cases.CaseError as error:
            print(f"Refused: {news_watcher.printable(str(error), 300)}.")
            return 1

    facts, origin = case.facts, case.meta["origin"]
    sbom_info = origin.get("sbom") if isinstance(origin.get("sbom"), dict) else {}
    sbom_path = args.sbom or sbom_info.get("path")
    config_path = args.config or origin.get("config_path")
    if not cases.is_local_path(sbom_path) or not cases.is_local_path(config_path):
        print("Refused: the case points to a network path for the SBOM or the config. Use --sbom and --config with local files.")
        return 1
    if not isinstance(sbom_path, str) or not isinstance(config_path, str) or not isinstance(sbom_info.get("sha256"), str):
        print("Refused: the case does not say which SBOM and config it came from. Use --sbom and --config, or draft it again.")
        return 1

    # 1. Rebuild the facts from the SBOM, the config and the saved data. Nothing from the case folder is trusted.
    expected_product = {key: facts[key] for key in ("manufacturer", "product_name", "member_states")}
    expected = {"component": facts["component"], "version": facts["version"], "exploited_cve": facts["cve_id"],
                "exploited_via": facts["exploited_via"], "exploited_cve_matched_on": facts["cve_matched_on"]}
    try:
        config, components, sbom_sha256 = rederive.load_inputs(sbom_path, config_path, sbom_info["sha256"], expected_product)
        finding, _, feeds = rederive.rederive(components, config, expected, args.cache, args.evidence, args.now)
        awareness = datetime.fromisoformat(facts["awareness_time_utc"])
        rebuilt = report_facts.build_facts(config, finding, kev_ids=feeds.kev_ids, evidence_dir=args.evidence, awareness=awareness)
        earliest, earliest_why = aw.earliest_allowed(rebuilt["exploited_via"], rebuilt["cve_id"], feeds.kev, rebuilt["evidence"]["date"])
    except (SbomError, ConfigError) as error:
        print(f"Refused: {news_watcher.printable(str(error), 300)}")
        return 1
    except (rederive.RederiveError, report_facts.FactsError, aw.AwarenessError, ValueError) as error:
        print(f"Refused: {news_watcher.printable(str(error), 400)}.")
        return 1
    if rebuilt != facts:
        differing = sorted(key for key in set(rebuilt) | set(facts) if rebuilt.get(key) != facts.get(key))
        print(f"Refused: the facts in the case differ from the facts rebuilt now from the SBOM and the saved data: "
              f"{', '.join(differing)}.")
        return 1
    first_at, first_file = _first_found(origin)
    verdict = aw.check_awareness(awareness, args.now(), aw.Observation(first_at, first_file, earliest, earliest_why))
    if verdict.refusals:
        for line in verdict.refusals:
            print(f"Refused: {news_watcher.printable(line, 500)}")
        return 1

    # 2. Run the fact checker again on the draft as it is on disk. The saved check.json is ignored.
    check = fact_checker.check_reports(rebuilt, case.reports)
    print(f"Fact check (run again now, check.json is ignored): {check.status}")
    if not check.ok:
        for item in check.problems:
            print(f"  - {news_watcher.printable(item, 300)}")
        print("Refused: the draft does not pass the fact check.")
        return 1
    try:
        approved = {lang: report_template.approved_report(case.reports[lang], lang) for lang in report_facts.LANGUAGES}
    except report_facts.FactsError as error:
        print(f"Refused: {news_watcher.printable(str(error), 300)}.")
        return 1

    # 3. Show everything and ask the human.
    kev_info = None
    if rebuilt["exploited_via"] == "kev":
        entry = next((e for e in feeds.kev["vulnerabilities"] if e.get("cveID") == rebuilt["cve_id"]), None)
        kev_info = {"date_added": entry["dateAdded"] if entry else None, "date_released": feeds.kev.get("dateReleased"),
                    "downloaded_at": feeds.kev_status.get("downloaded_at")}
    suspicious = report_facts.claim_word_warnings(rebuilt)
    if suspicious:
        print(f"WARNING: {', '.join(suspicious)} contain(s) a word that reads like a statement (approved, sent, safe, fixed ...). "
              "Check the wording of these names.")
    age_warning = _kev_age_warning(feeds.kev_status, args.now())
    if age_warning:
        print(age_warning)
    for line in verdict.warnings:
        print(news_watcher.printable(line, 600))
    typed_reason = (origin.get("awareness") or {}).get("reason") if isinstance(origin.get("awareness"), dict) else None
    if typed_reason:
        print(f"Reason typed when the case was drafted (why the awareness time is later than the first run): "
              f"{news_watcher.printable(typed_reason, 300)}")
    tool_deadline = first_at + report_facts.AWARENESS_WINDOW if first_at else None
    if tool_deadline:
        print(f"By the tool's own clock (first run that found the case + 24 hours) the deadline would be: "
              f"{_berlin_and_utc(tool_deadline.isoformat())}")
        if datetime.fromisoformat(rebuilt["deadline_utc"]) > tool_deadline:
            print("WARNING: the deadline in this report is LATER than the tool's own clock allows. Make sure the awareness "
                  "time is right before you approve.")
    if datetime.fromisoformat(rebuilt["deadline_utc"]) < args.now() or (tool_deadline and tool_deadline < args.now()):
        print("WARNING: THE 24-HOUR DEADLINE HAS ALREADY PASSED. Report as soon as possible and tell your CSIRT why it is late.")
    _print_case_screen(case, rebuilt, kev_info, approved)
    print("\nYou are about to approve this text. This tool never sends anything: you submit it by hand.")

    answer = _ask(args, f"Type the case id ({case.case_id}) to confirm that you read the text above: ")
    if answer is None or answer != case.case_id:
        print("Cancelled (the case id was not typed exactly). Nothing was approved.")
        return 1
    answer = _ask(args, 'Are the manufacturer, product, component, version, CVE, awareness time and Member States above correct? Type the word "yes": ')
    if answer is None or answer.strip() != "yes":
        print("Cancelled. Nothing was approved.")
        return 1
    answer = _ask(args, "Type your name (it is saved in approvals.log; it is not a login): ")
    name = news_watcher.clean_human_name(answer) if answer is not None else None
    if name is None:
        print("Cancelled (the name is empty, too long or has special characters). Nothing was approved.")
        return 1

    # 4. Nothing may have changed while the human was deciding: the case files, the SBOM, the config and the saved data.
    try:
        now_case = cases.load_case(args.cases, args.case_id)
        raw_sbom = read_sbom_bytes(sbom_path)
        config_again, components_again, _ = rederive.load_inputs(sbom_path, config_path, sbom_info["sha256"], expected_product)
        finding_again, _, feeds_again = rederive.rederive(components_again, config_again, expected, args.cache, args.evidence, args.now)
        rebuilt_again = report_facts.build_facts(config_again, finding_again, kev_ids=feeds_again.kev_ids,
                                                 evidence_dir=args.evidence, awareness=awareness)
    except (cases.CaseError, SbomError, ConfigError, rederive.RederiveError, report_facts.FactsError):
        print("Cancelled: the case or the SBOM changed while you were deciding. Nothing was approved.")
        return 1
    if (any(now_case.sha256[key] != case.sha256[key] for key in ("draft", "facts", "case", "check"))
            or hashlib.sha256(raw_sbom).hexdigest() != sbom_sha256 or rebuilt_again != rebuilt):
        print("Cancelled: the case or the SBOM changed while you were deciding. Nothing was approved. Look at it and run the command again.")
        return 1

    # 5. Save: approved.md, then ONE line in approvals.log, then the status.
    when = args.now().isoformat()
    try:
        approved_sha256 = cases.write_approved(args.cases, case.case_id, approved)
        approval = {"approver": name, "approved_at": when, "draft_sha256": case.sha256["draft"],
                    "facts_sha256": case.sha256["facts"], "sbom_sha256": sbom_sha256, "approved_sha256": approved_sha256}
        cases.append_approval_log(args.cases, {"time": when, "case_id": case.case_id, "approver": name,
                                               "draft_sha256": approval["draft_sha256"], "facts_sha256": approval["facts_sha256"],
                                               "sbom_sha256": sbom_sha256, "approved_sha256": approved_sha256})
        used = {**origin, "sbom": {**sbom_info, "path": str(Path(sbom_path).resolve())},
                "config_path": str(Path(config_path).resolve())}  # the files that were really used (they may have moved)
        cases.save_meta(args.cases, case.case_id, {**case.meta, "origin": used, "status": cases.STATUS_APPROVED, "approval": approval})
    except (cases.CaseError, OSError) as error:
        print(f"The approval could NOT be saved completely ({type(error).__name__}). The case is NOT approved. "
              f"If a line for it was already added to approvals.log, running the command again adds a second line. "
              f"Look at cases/{case.case_id}.")
        return 1
    print(f"\nApproved by {news_watcher.printable(name, 80)}. Saved: cases/{case.case_id}/approved.md and one line in cases/approvals.log.")
    print("Any later change to the draft, the facts or the SBOM means this case must be approved again.")
    print("Nothing was sent. This tool has no send function: you submit approved.md by hand "
          "(ENISA Single Reporting Platform, EU Login). A human decides what happens next.")
    return 0


def close_command(args):
    """0 = marked (or already marked), 1 = refused or cancelled, 2 = the case id / case cannot be used.
    For a HUMAN: the tool cannot know whether the report was really submitted. It sends nothing."""
    try:
        case = cases.load_case(args.cases, args.case_id)
    except cases.CaseError as error:
        print(f"REJECTED: {news_watcher.printable(str(error), 300)}.")
        return 2
    state = cases.approval_state(case)
    if state != cases.STATUS_APPROVED:
        print(f"Refused: only an approved case can be marked as submitted (this one is {state}).")
        return 1
    if cases.is_closed(case):
        print(f"The case {case.case_id} is already marked as submitted. Nothing to do.")
        return 0
    facts = case.facts
    _say(f"Case {case.case_id}: {facts['cve_id']} in {facts['component']} {facts['version']}, "
         f"deadline {report_facts.format_time(facts['deadline_utc'], 'en')}")
    print("Marking it as submitted means: YOU sent approved.md yourself (ENISA Single Reporting Platform). "
          "This tool sent nothing and cannot check it.")
    answer = _ask(args, f"Type the case id ({case.case_id}) to confirm: ")
    if answer is None or answer != case.case_id:
        print("Cancelled (the case id was not typed exactly). Nothing was changed.")
        return 1
    answer = _ask(args, 'Did you submit this report by hand? Type the word "yes": ')
    if answer is None or answer.strip() != "yes":
        print("Cancelled. Nothing was changed.")
        return 1
    answer = _ask(args, "Type your name (it is saved in closed.log; it is not a login): ")
    name = news_watcher.clean_human_name(answer) if answer is not None else None
    if name is None:
        print("Cancelled (the name is empty, too long or has special characters). Nothing was changed.")
        return 1
    try:
        cases.write_closed(args.cases, case, name, args.now().isoformat())
    except (cases.CaseError, OSError) as error:
        print(f"The mark could NOT be saved ({type(error).__name__}). The case stays open.")
        return 1
    print(f"\nThe case {case.case_id} is marked as submitted by {news_watcher.printable(name, 80)}. It leaves the open list.")
    print("Nothing was sent. This tool has no send function. A human decides what happens next.")
    return 0


# ---------------------------------------------------------------- the end of `cra run`: open cases

MAX_OPEN_SHOWN = 10
OPEN_LIST_SECONDS = 20  # the scheduled run has a time limit: this list must never use it up
_SHELL_SPECIAL = set('"$`%&;^|<>!\'\n')


def _time_left(deadline, now):
    if deadline >= now:
        return f"{aw._span(deadline - now)} left"
    return f"OVERDUE by {aw._span(now - deadline)}"


def _options(folders, defaults, names):
    """(' --cache "X" --cases "Y"', True) for the folders that differ from the default ones, so a ready-made command
    works on the same folders as this run. (text, False) when a folder name has characters that are risky when pasted."""
    text = ""
    for name in names:
        value = folders.get(name)
        if value is None or Path(value).resolve() == Path(defaults[name]).resolve():
            continue
        if _risky(value):
            return "", False
        text += f' --{name} "{value}"'
    return text, True


def print_open_cases(cases_root, now, product, report_findings, run_path, sbom_path, config_path, folders=None, defaults=None):
    """A short list of the cases a human still has to act on, most urgent deadline first, and the possible report cases
    of this run that have no draft yet. Reads only; creates nothing."""
    folders = folders or {}
    defaults = defaults or {}
    print("\nOPEN CASES (a human must act on these):")
    close_options, close_options_ok = _options(folders, defaults, ("cases",)) if defaults else ("", True)
    approve_options, approve_options_ok = _options(folders, defaults, ("cases", "cache", "evidence")) if defaults else ("", True)
    found, unreadable = cases.list_cases(cases_root)
    entries = []
    started = time.monotonic()
    for case in found:
        if time.monotonic() - started > OPEN_LIST_SECONDS:
            print(f"  WARNING: the list was cut short after {OPEN_LIST_SECONDS} seconds. Look in the cases folder.")
            break
        try:
            state = cases.approval_state(case)
            deadline = datetime.fromisoformat(case.facts["deadline_utc"])
            tool_deadline = _tool_deadline(case.meta)
            effective = min(deadline, tool_deadline) if tool_deadline else deadline  # the earlier of the two counts
        except Exception:  # one broken case must not hide the others
            print(f"  WARNING: the case {case.case_id} could not be judged (internal error). Look at it by hand.")
            continue
        if state == cases.STATUS_APPROVED and cases.is_closed(case):
            continue  # a human marked it as submitted by hand
        entries.append((effective, deadline, tool_deadline, case, state))
    entries.sort(key=lambda entry: (entry[0], entry[3].case_id))
    if not entries:
        print("  No open cases.")
    for effective, deadline, tool_deadline, case, state in entries[:MAX_OPEN_SHOWN]:
        facts = case.facts
        print(news_watcher.printable(
            f"  {case.case_id}  {state:<8} {facts['cve_id']} in {facts['component']} {facts['version']}  "
            f"deadline {report_facts.format_time(facts['deadline_utc'], 'en')}  [{_time_left(effective, now)}]", 400))
        if tool_deadline and tool_deadline < deadline:
            print(news_watcher.printable(
                f"    NOTE: by the tool's own clock (first run that found the case + 24 hours) the deadline is "
                f"{report_facts.format_time(tool_deadline.isoformat(), 'en')}. The awareness time that was typed is later.", 400))
        if effective < now:
            print("    THE 24-HOUR DEADLINE HAS ALREADY PASSED. Report as soon as possible and tell your CSIRT why it is late.")
        if state == cases.STATUS_PENDING:
            print(news_watcher.printable(f"    next: read it and approve it with  {cli_name.command('approve', case.case_id)}"
                                         + (approve_options if approve_options_ok else "  (add your --cases/--cache/--evidence folders)"), 700))
        elif state == "CHANGED":
            print(news_watcher.printable(f"    CHANGED since it was approved: it must be approved again with  {cli_name.command('approve', case.case_id)}"
                                         + (approve_options if approve_options_ok else "  (add your --cases/--cache/--evidence folders)"), 700))
        else:
            print("    approved: a human submits approved.md by hand (this tool never sends anything)")
            print(news_watcher.printable(f"    when you have submitted it, mark it with  {cli_name.command('close', case.case_id)}"
                                         + (close_options if close_options_ok else "  (add your --cases folder)"), 500))
    if len(entries) > MAX_OPEN_SHOWN:
        print(f"  ... and {len(entries) - MAX_OPEN_SHOWN} more open case(s) (look in the cases folder).")
    if unreadable:
        print(f"  WARNING: {len(unreadable)} case folder(s) cannot be read and need a human look: "
              f"{', '.join(news_watcher.printable(name, 40) for name in unreadable[:10])}")

    seen, missing = set(), []
    for finding in report_findings:
        key = (finding.get("component"), finding.get("version"), finding.get("exploited_cve"))
        if key in seen:
            continue
        seen.add(key)
        try:
            case_id = cases.make_case_id({"manufacturer": product["manufacturer"], "product_name": product["product_name"],
                                          "component": key[0], "version": key[1], "cve_id": key[2]})
            exists = cases.case_path(cases_root, case_id).exists()
        except (KeyError, TypeError, cases.CaseError):
            exists = False
        if not exists:
            missing.append(key)
    if missing:
        print("\nPOSSIBLE REPORT CASES WITHOUT A DRAFT YET (the 24-hour clock starts when your company becomes aware):")
        for component, version, cve in missing[:MAX_OPEN_SHOWN]:
            line = f"  {cve} in {component} {version}"
            paths = [str(run_path or ""), str(sbom_path), str(config_path)]
            draft_options, draft_options_ok = _options(folders, defaults, ("cases", "cache", "runs", "evidence")) if defaults else ("", True)
            if run_path and (any(_risky(p) for p in paths) or not draft_options_ok
                             or not matcher.CVE_PATTERN.fullmatch(str(cve))):
                line += f"  (a file name has special characters, so no ready-made command is shown: use `{cli_name.command('draft', '--help')}`)"
            elif run_path:
                line += f'  -> {cli_name.command("draft")} --run "{run_path}" --cve {cve} --sbom "{sbom_path}" --config "{config_path}"{draft_options}'
            else:
                line += f"  (this run could not be saved, so it cannot be drafted from: run `{cli_name.command('run')}` again)"
            print(news_watcher.printable(line, 3000))
        if len(missing) > MAX_OPEN_SHOWN:
            print(f"  ... and {len(missing) - MAX_OPEN_SHOWN} more.")
