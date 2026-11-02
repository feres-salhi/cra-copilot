# CRA Copilot

> A small, open-source tool that helps a small manufacturer notice when a vulnerability in one of their product's software components is actively exploited, and prepares a checked draft of the EU early warning for a human to review.

```mermaid
flowchart TD
    A["SBOM (CycloneDX JSON)"] --> B["sbom_reader"]
    B --> C["news_watcher (OSV + CISA KEV)"]
    C --> D["matcher"]
    D --> E["POSSIBLE REPORT CASE"]
    E --> F["draft: facts + approved sentences + fact checker"]
    F --> G["human approval"]
    G --> H["human submits by hand on the ENISA Single Reporting Platform"]
    S["scheduler (every 4 hours)"] --> R["run"]
    R --> W["Windows alert"]
    R -.-> B
```

## What this is

The EU Cyber Resilience Act (CRA), Article 14, says that a manufacturer must send an early warning within 24 hours when a vulnerability in their product is actively exploited. This duty applies from 11 September 2026.

For a small company that is hard: someone has to watch vulnerability news every day, compare it with the product's software parts, and write a report on time.

CRA Copilot does the watching and the comparing with normal, testable code. It reads a product's SBOM (the product's software ingredient list), downloads public vulnerability data, and tells you when a possible report case exists. It then prepares a German and English draft of the early warning, checks the draft with code, and stops. A human approves it and submits it by hand. The tool never sends anything.

Built as a portfolio project in product security and AI security.

## Key design rules

These rules come from [CLAUDE.md](CLAUDE.md) and shape every part of the code.

1. **The AI never decides whether a product is affected.** Only normal, testable code decides that. The AI only helps with wording.
2. **Every fact in a report comes from the input data.** Product names, components, versions, vulnerability IDs and dates must all come from the input. `fact_checker.py` rejects drafts that contain other facts.
3. **Only FAKE demo data** is used in `demo-data/`. No real company's product data.
4. **No API keys in code or on GitHub.** Keys live only in a `.env` file, and `.env` is git-ignored.
5. **No invented results.** This README only states what tests and runs actually showed.
6. **A human always approves.** The tool never sends anything. There is no send function, and a test scans `src/` to make sure it stays that way.

### Lesson: the AI chooses only approved sentences

At first the AI wrote free text and code tried to check it. That did not work. A forbidden-word list was beaten by reviewers, and so was an allowed-word list: a sentence made only of allowed words can still be false. Code cannot judge the meaning of free text.

A team meeting of AI agents agreed on a different design. The AI may only **choose** among a table of approved whole sentences (`src/summary_sentences.py`, 6 per language, written by a human). The checker accepts only those sentences, exactly. If the AI fails, the tool uses a fixed fallback paragraph. Fares confirmed this decision (P1) on 2026-11-02.

## How it works, step by step

All commands are PowerShell commands, run in the project folder on Windows.

**1. Run the whole check**

```powershell
.venv\Scripts\python -m src run --sbom demo-data\demo-thermostat-sbom.json --config demo-data\demo-product-config.json
```

This downloads real public data from OSV.dev and CISA KEV, matches it against the SBOM, and ends with a list of open cases and their deadlines. Exit codes: 0, 1, 2 or 3. Exit code 3 means a possible report case was found.

**2. Check the status**

```powershell
.venv\Scripts\python -m src status
```

Shows two clocks: the latest run, and the latest run where all sources were OK. It warns after 26 hours.

**3. Preview the draft (saves and sends nothing)**

```powershell
.venv\Scripts\python -m src preview-report --run runs\<file>
```

Prints the German and English draft. It works offline unless you add `--live-ai`.

**4. Create a draft case**

```powershell
.venv\Scripts\python -m src draft --run runs\<file> --sbom demo-data\demo-thermostat-sbom.json --config demo-data\demo-product-config.json
```

A human types the time they became aware of the problem, with a time zone. The tool re-derives "affected" from the SBOM on its own. It creates a PENDING case in `cases/<id>/`. The deadline is the awareness time plus 24 hours, shown in Berlin time and UTC.

**5. Approve the case**

```powershell
.venv\Scripts\python -m src approve <case-id>
```

The tool rebuilds the facts, re-runs the fact checker, and shows the full English and German text. You must type three answers: the case id, `yes`, and your name. No flag skips them. It writes `approved.md` and adds a line with sha256 fingerprints to `cases/approvals.log`.

**6. Close the case**

```powershell
.venv\Scripts\python -m src close <case-id>
```

After you have submitted the report by hand on the ENISA Single Reporting Platform, you mark the case as submitted. The tool sends nothing.

**7. Alerts**

```powershell
.venv\Scripts\python -m src alerts --test
.venv\Scripts\python -m src alerts --list
```

An alert is a Windows toast (a small pop-up) plus a line in `cache/alerts.log` with UTC and Berlin time. `run --no-alerts` turns alerts off.

Other commands: `kev accept-removals` and `check-sbom`.

### Schedule

`scripts/register-schedule.ps1` registers a Windows scheduled task that runs the check every 4 hours (max 30 minutes, current user only; `-WhatIf` is available). `scripts/unregister-schedule.ps1` removes it. See [scripts/README.md](scripts/README.md). The scripts were written and tested only by parsing; the assistant never ran them. Fares registered the task by hand on 2026-11-02, first with `-WhatIf`, then for real (state Ready). Screenshot 10 shows its runs.

## Setup

1. Create a Python virtual environment named `.venv` in the project folder.
2. Install the packages listed in `requirements.txt` (and `requirements-dev.txt` for the tests).
3. Run the tests:

```powershell
.venv\Scripts\python -m pytest
```

For the optional live AI step, put your key in a `.env` file (never commit it). Without it, the tool uses the fixed fallback text.

## Results

Only real numbers from test runs and scans are listed here.

### Test totals over time

| Date | Stage | Result |
|------|-------|--------|
| 2026-10-21 | Phase 1 + 2 | 407 passed, 3 skipped |
| 2026-10-25 | After Strix fixes | 445 passed, 3 skipped |
| 2026-10-26 | Phase 3 | 977 passed, 5 skipped |
| 2026-11-02 | After key-leak fix | 995 passed, 5 skipped |
| 2026-11-02 | Phase 4 | 1,232 passed, 3 skipped, 2 deselected |
| 2026-11-02 | Improvements | 1,319 passed, 3 skipped, 2 deselected |
| 2026-11-02 | Alerts (current) | 1,450 passed, 3 skipped, 2 deselected |

Note on skips: the skipped and deselected tests are the optional live tests (they only run when switched on) and one symlink test that this Windows account cannot run. If the 2 live tests are not deselected, the current total is 1,450 passed, 5 skipped.

### Bandit

`.venv\Scripts\python -m bandit -r src` found 0 issues of any severity at every run. Lines scanned over time: 1,537, then 2,569, then 3,802, then 3,908, then 4,455 (latest: 0 Low, 0 Medium, 0 High). The first report is [reports/bandit-2026-10-25.txt](reports/bandit-2026-10-25.txt).

### Strix scan

Strix is an AI-driven security testing tool. Setup of the run:

- Version 1.7.0, model Claude Haiku 5.5, quick mode, run on 2026-10-25
- About 100.7 million tokens (100,849,428), 456 requests, real cost $7.29 (the estimate given beforehand was about $0.75 to $3.75 for a quick scan)
- Scope: the runtime code in `src/`

It reported **11 findings: 0 Critical, 0 High, 2 Medium, 9 Low.** All were addressed. Each fix has a test that was written first. Two fixes are partial (vuln-0001 and vuln-0007, see Known limits).

| ID | Severity | Problem | Result |
|----|----------|---------|--------|
| vuln-0004 | Medium | A Maven component written with slashes or capitals was accepted as fine, OSV found nothing, so a Log4Shell component looked clean. | Now UNKNOWN. |
| vuln-0007 | Medium | A KEV list with exploited CVEs quietly removed was accepted as complete. | Now stale and INCOMPLETE, ids are printed, the old copy is kept (partial fix). |
| vuln-0001 | Low | A fake run file planted in the runs folder could make `status` say everything is fine. | Run records are sealed with a fingerprint. Unsealed or edited records count as incomplete (partial fix). |
| vuln-0002 | Low | `status` loaded every run file with no total size limit. | Keeps two runs in memory, plus a read budget. |
| vuln-0005 | Low | A fix and a re-introduction at the same version number sorted wrongly. | Order is kept, ambiguous ties are UNKNOWN. |
| vuln-0006 | Low | No OSV answer was still marked "known not exploited". | No longer. |
| vuln-0008 | Low | A KEV answer dated in the future froze the saved copy. | Rejected. |
| vuln-0009 | Low | The 120 s download limit was only checked between reads, so a slow-drip server could stall the run. | A total time limit now holds. |
| vuln-0011 | Low | An OSV id ending in a dot crashed the whole run. | No longer aborts. |
| vuln-0012 | Low | Two runs finishing in the same second overwrote each other. | The file name is claimed atomically. |
| vuln-0013 | Low | A run record over 20 MB was silently skipped by `status`. | Counts as incomplete. |

Strix also confirmed some controls: the SBOM limits held under about 30,000 fuzzed components and 3,000 file mutations, terminal-escape injection was blocked, path containment held, and redirects were refused.

Strix limits: it had no web search, and the KEV attack was only simulated. Strix was run only against Fares's own code. The full report is [reports/strix-2026-10-25/penetration_test_report.md](reports/strix-2026-10-25/penetration_test_report.md).

A first attempt with a free Gemini key failed, because the free tier allows only 20 requests per day per model.

### Live Log4Shell demo

Real public data from 2026-10-21 was matched against a fake demo product. Result:

- 2 possible report cases for `log4j-core 2.14.1`: CVE-2021-44228 (Log4Shell) and CVE-2021-45046. Both are in CISA KEV (KEV dateAdded 2021-12-10 and 2023-05-01).
- The component `smartheat-firmware-core` (no purl) was flagged UNKNOWN for a human.
- The run was marked RESULT INCOMPLETE.
- "Nothing was sent."

See screenshot 03 below.

### Live Gemini test (2026-11-02)

The first real call passed: mode `ai`, fact check PASS, model `gemini-3.5-flash` (screenshot 07). Later calls got HTTP 429 (free tier rate limit). The preview correctly used the fixed fallback text and said so.

### API-key leak found by Fares

When the live AI test failed, pytest printed the full Gemini API key on screen, because a traceback shows plain-text variables. Fares noticed it. The key was treated as burned and rotated.

The fix:

- The key now lives only inside a `Secret` box. It prints as `***`, and the real text is only available through `reveal()` when the request header is set.
- `http_fetch` drops inner error details.
- Tests print only the error type and status.
- pytest uses short tracebacks.

Reviewers found a second leak path in the first fix (inner steps of the web library). That was fixed too. There are 10 regression tests in `tests/test_key_never_leaks.py`; 7 of them fail on the old code. See screenshot 08. Known limit: the key can still be read by code that calls `reveal()`, and it stays in the normal process environment.

## Screenshots

![Design meeting of the AI agent team: the plan (2026-10-21)](screenshots/01a-design-meeting-plan.png)

![Design meeting of the AI agent team: the risks (2026-10-21)](screenshots/01b-design-meeting-risks.png)

![pytest: 407 passed, 3 skipped](screenshots/02-all-tests-pass.png)

![First live run with the Log4Shell demo product](screenshots/03-first-live-run-log4shell.png)

![Bandit scan](screenshots/04-bandit-scan.png)

![Strix findings](screenshots/05a-strix-findings.png)

![Strix recommendations and cost](screenshots/05b-strix-recommendations-cost.png)

![Tests after the Strix fixes](screenshots/06-tests-after-strix-fixes.png)

![First draft warning, Log4Shell](screenshots/07-first-draft-warning-log4shell.png)

![API-key leak fixed](screenshots/08-key-leak-fixed.png)

![Human approval](screenshots/09-human-approval.png)

![Scheduled run: LastTaskResult 3 is the exit code of the run, meaning a possible case was found](screenshots/10-scheduled-run.png)

![Desktop alert](screenshots/11-alert-notification.png)

## Known limits

Please read these before trusting the tool.

- **The local writer is trusted.** The run-record seal is a fingerprint, not a signature. Cache files and `approvals.log` are unsigned (decisions S7 and Q3).
- **KEV list authenticity is NOT verified.** An on-path attacker that TLS trusts could replay or swap the list. A first run, a damaged saved file or changed dates are not detected (decision S3).
- **KEV is a floor, not a ceiling.** A vulnerability can be actively exploited without being in KEV. Not being in KEV does not mean safe.
- Only the **PyPI and Maven** ecosystems are supported.
- Only **CycloneDX JSON** SBOMs are supported.
- The scheduler runs only while the user is logged in (a toast cannot show otherwise). `alerts.log` always has the alert.
- The Gemini free tier has rate limits (HTTP 429). The tool then uses the fixed fallback text.
- Dependencies are pinned, but the pins have no hashes (no hash pinning).
- The tool's checks use this computer's clock.
- The vendor and product of KEV entries are not shown. Compare the CVE id and date with the CISA site by hand.
- The assistant never showed a real toast itself. Fares ran `alerts --test` and saw the real toast on 2026-11-02 ("CRA Copilot alert - Test notification ..."); screenshot 11 is that capture. A toast cannot appear when nobody is logged in or Do Not Disturb is on, so `cache/alerts.log` always has the alert.
- The tool does not yet draft the user notice required by Article 14(8).
- A human decides everything legal.

## Lessons learned and what I would improve

Lessons:

- "No answer" or "well-formed" is not proof that a check was complete. If the tool is uncertain, the result must be UNKNOWN or INCOMPLETE, never "safe". This was the systemic theme of the Strix findings.
- Code cannot judge the meaning of free text, so the AI may only choose approved sentences.
- Secrets leak through error messages, not only through files.
- Tests must never make real network or AI calls by accident. A stray environment variable `CRA_LIVE_AI=1` caused real Gemini calls during review. The fix is to always unset it.
- AI subagent reviewers and an external scanner (Strix) found different things. Use both.

What I would improve:

- Phase 5: a Power BI dashboard. [docs/run-record-format.md](docs/run-record-format.md) describes the run record fields for it.
- E-mail alerts via Power Automate. This would be a new network path and needs a decision first.
- SPDX SBOM support.
- More ecosystems.
- Signed run records.
- A draft of the user notice (Article 14(8)).
- Re-run Strix on the current code.

## Repository structure

| Path | What it is |
|------|------------|
| `src/sbom_reader.py` | Reads the SBOM and treats the file as untrusted. |
| `src/news_watcher.py` | Downloads vulnerability data (OSV and CISA KEV). |
| `src/matcher.py` | Decides: affected? actively exploited? |
| `src/report_facts.py` | Builds the facts of one case, with one shared formatter for dates and text. |
| `src/report_template.py` | The fixed German and English early-warning template. |
| `src/summary_sentences.py` | The approved whole sentences the AI may choose from. |
| `src/report_writer.py` | The AI step that chooses sentences. |
| `src/fact_checker.py` | Code that checks every fact in the draft. |
| `src/env_loader.py` | Reads the `.env` file (the key is kept in a Secret box). |
| `src/awareness.py` | Handles the awareness time a human types. |
| `src/rederive.py` | Re-derives "affected" from the SBOM. |
| `src/cases.py`, `src/case_commands.py` | Case folders and the draft, approve and close commands. |
| `src/alerts.py`, `src/toast.py` | Alert rules, `alerts.log` and the Windows toast. |
| `src/safe_paths.py` | Safe path handling. |
| `src/cli.py`, `src/cli_name.py` | The command line. |
| `tests/` | Automatic tests (pytest). |
| `demo-data/` | Fake example products only. |
| `scripts/` | Schedule scripts, see [scripts/README.md](scripts/README.md). |
| `docs/run-record-format.md` | Fields of the run record. |
| `reports/` | Bandit and Strix reports. |
| `screenshots/` | Numbered proof screenshots. |
| `.github/workflows/gitleaks.yml` | Secret scan. Actions are pinned to full commit SHAs. |
| [PLAN.md](PLAN.md) | The plan from the design meeting. |
| [QUESTIONS.md](QUESTIONS.md) | Open questions and the decisions Fares made. |
| [PROGRESS.md](PROGRESS.md) | Progress record. |
| [CLAUDE.md](CLAUDE.md) | The project rules. |
| [LAB-NOTES.md](LAB-NOTES.md) | A dated diary of the work. |
| [LICENSE](LICENSE) | MIT. |

## Legal and ethics note

This is a student project. It is not legal advice. It uses a fake demo product only and never sends anything. Strix was run only against Fares's own code. Nothing here replaces reading Article 14 and the ENISA guidance. Section (g) of [PLAN.md](PLAN.md) has the summary of the CRA legal check, which was done on 2026-10-25.

## Kurzfassung (Deutsch)

CRA Copilot ist ein Open-Source-Werkzeug für kleine Hersteller. Nach dem EU Cyber Resilience Act (Artikel 14) müssen sie innerhalb von 24 Stunden eine Frühwarnung senden, wenn eine Schwachstelle in ihrem Produkt aktiv ausgenutzt wird. Das Werkzeug liest die SBOM des Produkts und lädt öffentliche Schwachstellendaten von OSV und CISA KEV herunter. Normaler, testbarer Code entscheidet, ob ein Produkt betroffen ist; die KI entscheidet das nie. Die KI darf nur aus fest freigegebenen Sätzen auswählen, und ein Faktenprüfer lehnt jeden Entwurf mit fremden Fakten ab. Ein Mensch muss jeden Bericht freigeben und selbst bei ENISA einreichen, denn das Werkzeug sendet nie etwas. Es ist ein Studentenprojekt, keine Rechtsberatung, und es nutzt nur erfundene Demo-Daten.

## Author

Fares Salhi, TU Darmstadt

- GitHub: https://github.com/feres-salhi
- Portfolio: https://faressalhi.com
- LinkedIn: https://www.linkedin.com/in/fares-salhi-03b53530a
