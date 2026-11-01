"""Phase 4: the commands that work with cases: `cra draft` (and `cra approve`).

Both are for a HUMAN at a keyboard. Piped input or a scheduled task cancels them, and there is no flag that answers a
question for the human (CLAUDE.md rule 6). Nothing here sends anything: there is no send function in this tool.
"""

import json
from pathlib import Path

from src import awareness as aw
from src import cases, matcher, news_watcher, report_facts, report_writer

MAX_TRIES = 3
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
        return 0
    if not news_watcher.run_is_complete(run):
        print("Note: this run was INCOMPLETE (a source or a component could not be fully checked), so more cases may exist.")
    finding = _choose(args, candidates)
    if finding is None:
        print("Cancelled. Nothing was created.")
        return 1

    kev, kev_meta = news_watcher.load_kev_cache(args.cache, args.now)
    kev_ids = news_watcher.kev_cve_ids(kev) if kev else None
    try:
        facts = report_facts.build_facts(run.get("product"), finding, kev_ids=kev_ids, evidence_dir=args.evidence)
    except report_facts.FactsError as error:
        print(f"Nothing was created: the facts of this case cannot be built ({news_watcher.printable(str(error), 300)}).")
        return 1
    case_id = cases.make_case_id(facts)
    if cases.case_path(args.cases, case_id).exists():
        print(f"Nothing was created: the case {case_id} already exists. Use `cra approve {case_id}` or look at cases/{case_id}.")
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
        facts = report_facts.build_facts(run.get("product"), finding, kev_ids=kev_ids, evidence_dir=args.evidence,
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
    print(f"Next: read the text and approve it with:  cra approve {created}")
    print("Nothing was sent. A human decides what happens next.")
    return 0
