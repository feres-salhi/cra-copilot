# Progress Log

## Summary for Fares (written when the autopilot stopped — Phase 3 was NOT started)

**What is done**
- **Phase 1** (safe foundation + SBOM reader) and **Phase 2** (download + matching) are built, tested, reviewed and committed. Nothing was pushed to GitHub; no `.env` was created.
- You can try it from the project folder (PowerShell), using the project's own Python:
  - `.venv\Scripts\python -m src check-sbom demo-data\demo-thermostat-sbom.json --config demo-data\demo-product-config.json` — lists the components of the fake product.
  - `.venv\Scripts\python -m src run --sbom demo-data\demo-thermostat-sbom.json --config demo-data\demo-product-config.json` — downloads the real public data (OSV.dev and CISA KEV) and checks the product. Exit code 3 means "report case found".
  - `.venv\Scripts\python -m src status` — shows when the last good run was, with loud warnings.
  - Tests: `.venv\Scripts\python -m pytest`.
- With the real data of 2026-10-21, the fake product has **two report cases** (log4j-core 2.14.1 with Log4Shell, CVE-2021-44228, and CVE-2021-45046 — both are in the KEV list); `smartheat-firmware-core` (no purl) is flagged for a human; the run is marked **RESULT INCOMPLETE** because of it. This is the intended, honest behaviour.

**Test totals (real numbers):** 407 passed, 3 skipped, 0 failed. The 3 skipped tests are 2 optional live tests (switch on with `CRA_LIVE_TEST=1`; they passed when I ran them once) and 1 symlink test that this Windows account is not allowed to run.

**Open questions** (full list with my temporary choices: `QUESTIONS.md`): when this summary was written, #2 (pin the GitHub Actions to commit codes *before the first push*), #5 (run `cra run` more often than daily, because the 26-hour warning can come after the 24-hour deadline) and #8 (Strix scan and a real penetration test) were open. **All three were decided by Fares on 2026-10-21** (see the update below). The other rows are small and temporary.

**What needs you next**
1. Read `QUESTIONS.md`. Questions #2, #5 and #8 are now **decided by Fares (2026-10-21)**; the other rows are small temporary choices.
2. Before the first push to GitHub: run the secrets check again (it passed twice), and pin all GitHub Actions to exact commit SHAs (decided, QUESTIONS.md #2). I could not look the SHAs up myself.
3. Phase 3 needs the legal check of the CRA Article 14 text (PLAN.md question 7, you decided to do it with an outside reviewer) **before** I write any report text.
4. Strix scans (Phase 1 and Phase 2): **pending** until Fares has a free Google Gemini API key (decided: quick mode; QUESTIONS.md #8).
5. The penetration-tester agent's Phase 2 review was **not completed** (a safety stop); see "End of Phase 2" below.


**Update, 2026-10-21 (after the autopilot stopped) — recorded from Fares**
- **Decisions:** QUESTIONS.md #2 (pin GitHub Actions to exact commit SHAs before the first push), #5 (run `cra run` every 4 hours with Windows Task Scheduler, to be set up in Phase 4) and #8 (free Google Gemini API key for Strix scans in quick mode; Phase 1 and 2 scans run once the key exists, until then pending) are marked DECIDED. New section "Later improvements (after Phase 3)" in QUESTIONS.md.
- **Real current test total, run by Fares himself on 2026-10-21: 407 passed, 3 skipped** — the same as my own count above. His proof screenshots are in `screenshots/`: `01a-design-meeting-plan.png`, `01b-design-meeting-risks.png`, `02-all-tests-pass.png`, `03-first-live-run-log4shell.png`.
- **What the screenshots show (I opened 02 and 03):**
  - `02-all-tests-pass.png` shows the pytest run in PowerShell: "407 passed, 3 skipped in 7.85s".
  - `03-first-live-run-log4shell.png` shows a real `cra run` output: two report cases for log4j-core 2.14.1 (CVE-2021-45046 and CVE-2021-44228, both in KEV), the firmware component flagged UNKNOWN, "RESULT INCOMPLETE", and "Nothing was sent".
  - I did not open `01a` and `01b`, so I only know them by their names.

---

## Entries before the autopilot (done together with Fares)

- **Piece 1** — `.gitignore` blocks `cases/`, `cache/`, `runs/`; `.env.example` holds only a placeholder key line.
- **Piece 2** — private Python toolbox `.venv` with pytest; `requirements-dev.txt` pins `pytest==9.1.1`.
- **Piece 3** — fake demo product in `demo-data/` (SBOM + config). It is fictional.
- **Piece 4a** — basic SBOM reader `src/sbom_reader.py`. 21 tests passed at that point. Reviewers' serious findings (nested components dropped, purl not checked against name/version, untrimmed versions) were fixed.

---

## Piece 4b — SBOM reader protections (Phase 1)

**What I built:** the SBOM reader now treats the file as possibly hostile. It rejects the *whole* file if it is bigger than 10 MB, nested deeper than 32 levels, has more than 5,000 components, or repeats a JSON key. A component with a strange name, version or purl becomes UNKNOWN (only that component) and the strange text is thrown away. It also reads the product config file (product name, manufacturer, EU countries) with its own checks, and gives warnings for an SBOM with no dependency list or no components.

**Why:** an SBOM comes from outside, so it could be broken or hostile. The tool must not crash, and strange text must never travel on into a legal report (PLAN.md risk 6).

**New words**
- *Hostile input* — a file that someone made on purpose to confuse or break a program.
- *Nesting depth* — how many boxes sit inside boxes inside boxes in a JSON file.
- *Duplicate key* — the same label used twice in one JSON box; it is unclear which value is meant, so we refuse the file.
- *Allowlist* — a short list of characters that are allowed; everything else is refused.
- *Canonical* — the one standard way to write something, so two spellings of the same thing look identical.
- *Qualifier / subpath* — extra optional parts at the end of a purl (after `?` or `#`) that can point somewhere else.
- *byte-order mark* — an invisible marker some Windows programs put at the start of a text file.

**Tests:** 82 passed, 0 failed (`pytest`). The demo SBOM still gives 5 components.

**Reviewer findings and what I did**
- *Both reviewers:* odd purls (`%72equests`, `?repository_url=...#sub`, a PyPI purl with a namespace) could still come out "OK". **Fixed:** these characters are refused, a PyPI purl must not have a namespace, and the stored purl is rebuilt in canonical form.
- *Code reviewer:* an empty `member_states` was accepted. **Fixed:** the config is rejected (a report with nobody to notify makes no sense).
- *Code reviewer:* the config size limit could be bypassed by a file growing between the check and the read. **Fixed:** read the bytes first, then check their length.
- *Auditor:* the config had no depth check. **Fixed:** same depth check as the SBOM.
- *Auditor (small):* switched to a faster queue for walking nested components.
- *Not changed:* the auditor measured about 1.4 seconds and 266 MB of memory for a 10 MB file full of tiny components. PLAN.md says 10 MB, so I kept it (low risk for a command-line tool). Written here so Fares can lower it if wanted.
- *Test gaps:* added tests for the error paths the reviewer listed.

**How it connects:** this is the front door of the whole tool. Everything later (matcher, report) only sees components that passed this door, and anything unclear arrives as UNKNOWN, never "safe".

**Open question:** empty SBOM handling is written in QUESTIONS.md as temporary decision #1.

---

## Piece 5 — Command-line skeleton and secret-scan workflow (Phase 1)

**What I built:** `src/cli.py` (run with `python -m src check-sbom <file> --config <file>`) that lists the components of an SBOM and what is UNKNOWN. Exit codes: 0 all fine, 1 some component UNKNOWN, 2 file rejected. Errors go to the error channel. Also `.github/workflows/gitleaks.yml`, a GitHub "robot" that will scan every upload for keys and passwords (it does nothing until the project is on GitHub; I did not push anything).

**Why:** the plan wants a `cra` tool; this is the empty frame the later commands (`run`, `status`, ...) plug into. The secret scan is risk 9 in PLAN.md.

**New words**
- *CLI (command-line interface)* — a program you use by typing a command, not by clicking.
- *Exit code* — a small number a program returns when it ends, so scripts can tell "fine" from "problem".
- *stderr* — the separate output channel programs use for error messages.
- *CI (continuous integration)* — a robot on GitHub that runs checks automatically on every upload.
- *gitleaks* — a free tool that searches files and history for accidentally saved passwords and keys.
- *Pinning* — fixing an add-on to one exact, unchangeable version so nobody can swap it later.

**Tests:** 4 CLI tests first, then 8 after the review (including "hostile text is never printed"). Whole project at this point: 147 passed, 0 failed (this number also includes the not-yet-committed news watcher tests, written for the next piece).

**Reviewer findings and what I did**
- *Reviewer + auditor (same point):* the workflow would probably fail on pull requests without `pull-requests: read`. **Fixed.**
- *Auditor:* the checkout step leaves the GitHub token on disk. **Fixed** (`persist-credentials: false`).
- *Reviewer:* exit code was 0 even with UNKNOWN components. **Fixed** (now 1).
- *Reviewer:* a Windows console could crash on unusual characters. **Fixed** (unprintable characters are replaced).
- *Auditor:* reading a path that is a folder/device could hang; the config was read before its size was checked. **Fixed:** files are read with a size limit and only if they are real files.
- *Auditor (cosmetic):* an unknown version printed as `None`. **Fixed** (prints `?`).
- *NOT fixed:* pinning the GitHub Actions to commit codes (reviewer + auditor, low/medium). I cannot look the codes up with my allowed network sources and must not invent them. Written as question #2 in QUESTIONS.md.
- *Checked clean by the auditor:* no terminal-escape text from an SBOM can reach the screen.

**How it connects:** this is the front panel of the tool. Part 2 and 3 will add `run` and `status` here.

---

## End of Phase 1 — review meeting and secrets check

**Who met:** three AI reviewers — a *security architect* (judges the design), a *penetration tester* (a friendly attacker who tries to break the code) and a *code reviewer* (also the judge who keeps things simple). Two rounds, as allowed. The secrets check was done by a separate *secrets and credential hygiene* reviewer.

**Round 1 — what they found**
- *Penetration tester:* tried about 11 kinds of attacks (device names like `NUL`, deeply nested files, duplicate keys, huge files, odd encodings, control characters, fake purls, a flood of components). **None succeeded.**
- *Code reviewer:* real SBOM tools often write `?type=jar` at the end of a purl, and my reader marked all of those UNKNOWN. **Must fix.** Also two tests were too weak and some code branches could never run.
- *Security architect:* an empty SBOM could look like "all clear"; a shared safe-path helper is needed before Phase 2 writes files; key-file names missing in `.gitignore`; GitHub Actions should be pinned; supply chain (hash pinning, pip-audit) is thin.

**Round 2 — what I did, and what they said**
- Accepted harmless purl qualifiers `type` and `classifier` and removed them from the stored purl (anything else → UNKNOWN).
- An SBOM with no components or no dependency list now prints **RESULT INCOMPLETE** and exits with code 1.
- New `src/safe_paths.py` (`safe_join`): one place that refuses `..`, slashes, drive letters, Windows device names (`CON`, `NUL`...), trailing dots and symlinks that leave the folder.
- `NaN` / `Infinity` are rejected; dead code removed; two weak tests now check the exact reason.
- `.gitignore` now also blocks `*.pem`, `*.key`, `*.p12`, `credentials*.json`, `secrets.*` and `.claude/settings.local.json`.
- The pen tester re-attacked the new code and found three small gaps (duplicate/empty qualifier keys, Maven group not character-checked or compared to the SBOM's `group`, `safe_join` allowing device names). **All three fixed and tested.**
- Verdicts: security architect **agrees**, code reviewer **agrees**, penetration tester found **no way to get a wrong package to "OK"**.

**Decisions left as they are (written down honestly)**
- *No hash-pinning, pip-audit or lockfile* (architect, "overkill for a student project"). The README must say the pins have **no hashes** and must not claim supply-chain hardening.
- *No local pre-commit secret scan* — PLAN.md calls it optional. It is OK only because nothing is pushed yet.
- *GitHub Actions pinned only to version tags.* Needs Fares before the first push (QUESTIONS.md #2).
- The 10 MB file limit can use about 266 MB memory in a worst case (PLAN.md number kept).

**Secrets check (secrets and credential hygiene reviewer): PASS.** No keys, passwords or tokens in the working files or in the whole git history (checked 11 commits). `.env` does not exist and is ignored; `.env.example` holds only the placeholder; `cases/`, `cache/`, `runs/` are ignored. `gitleaks` itself is not installed here, so its own scan did not run — the search used pattern matching (narrower than gitleaks). A second secrets check will be run at the end of Phase 2 before finishing.

**Strix scan pending** (no API budget).

**Tests at the end of Phase 1 work:** 294 passed, 1 skipped, 0 failed. (The skipped test needs permission to create symlinks, which this Windows account does not have; so the "symlink that points outside is refused" test did **not** run here. `safe_join` does resolve paths, but that one check is not proven by a test on this computer.) This number also contains the Phase 2 tests already written.

**How it connects:** Phase 1 is the safe front door: nothing hostile or unclear gets past the SBOM reader as "OK", and the path helper protects all later file writing.

---

## Piece 6 — News watcher `src/news_watcher.py` (Phase 2)

**What I built:** the part that downloads public vulnerability data from two free sources, without any key: **OSV.dev** (which vulnerabilities hit which package versions) and the **CISA KEV list** (vulnerabilities known to be used in real attacks). Everything is saved on disk in `cache/`; each run writes a status file in `runs/`. The most important rule: **a failed or half-finished download can never look like "nothing new"**. Each source is `ok` (fresh), `stale` (we had to use an older saved copy) or `failed`. A component OSV did not answer about becomes UNKNOWN, never "no vulnerabilities".

**Real data used for the tests (saved in `tests/fixtures/`):** the full CISA KEV list downloaded on 2026-10-21 (1,754 entries, catalog version 2026.10.20) and 17 real OSV records plus one real OSV batch answer for the demo components. Tests use a *fake internet* that serves these saved copies, so no test needs the real internet.

**Things from PLAN.md marked "(to verify)" that I checked against this real data**
- OSV batch answers contain only IDs (and a `modified` time), details need a second request per ID — **true**.
- Log4Shell (CVE-2021-44228) is in KEV, `dateAdded` **2021-12-10** — **true**.
- CVE-2021-45046 **is** in KEV (added 2023-05-01) — the plan did not know this.
- CVE-2023-32681 (requests) is **not** in KEV — true.
- Log4Shell's OSV record (GHSA-jfh8-c2jp-5v3q) has three affected ranges: 2.13.0–2.15.0, 2.0-beta9–2.3.1 and 2.4–2.12.2 (the Java 7 branch), and the exact-version list contains `2.0-beta9` — true.
- CVE-2021-45046 is fixed in 2.16.0 (and 2.12.2 on the old branch) — true.
- requests: fixed in 2.31.0 — true.
- **A surprise the plan did not know:** OSV also lists newer, real vulnerabilities for `log4j-core 2.17.1` (for example CVE-2026-34480, CVE-2026-34477, CVE-2025-68161). So in today's data even the "fixed" 2.17.1 is not clean. The Log4Shell *test* is still right (2.17.1 is not affected by Log4Shell).
- **A quirk in OSV's data:** the same `modified` time has 6 decimals in a batch answer and 9 in a full record. My first "unchanged since last time" check never matched; found by a test and fixed.

**New words**
- *Fixture* — a saved copy of real data that tests use instead of the internet.
- *Cache* — a folder of saved downloads, so we can fall back to them.
- *Stale* — data that is old because the new download failed.
- *Retry / backoff* — trying a failed download again after waiting a little, a bit longer each time (1, 2, 4 seconds).
- *HTTP 429* — the server's way of saying "you ask too often".
- *Pagination* — an answer that comes in pages; you must ask for every page.
- *sha256 fingerprint* — a long code computed from a file; any change in the file changes the code.
- *Replay* — someone feeding the tool an old, genuine file to make it think nothing is new.
- *Redirect* — a server telling you "go to this other address"; we refuse them.

**Tests:** `tests/test_news_watcher.py` — see the totals in the phase summary below. Examples: 429 retried then OK; 429 forever → failed (never "empty"); cut-off download retried; KEV with a missing field / wrong count / drop above 5% / old release date / duplicate IDs rejected; stale fallback marks `stale`; many pages; more than 500 components in chunks; IDs like `../../x` rejected; Windows device names never become file names; the 26-hour warning; "RESULT INCOMPLETE" text.

**Reviewer findings and what I did**
- *Both:* components that were never asked about (no purl / UNKNOWN) and an empty list still gave OSV status `ok`. **Fixed:** the run now counts `checked` and `unchecked`; `complete` is true only if all sources are ok **and** nothing was skipped **and** at least one component was checked.
- *Reviewer:* some download errors (cut-off body, `IncompleteRead`) escaped as raw errors and skipped the stale fallback. **Fixed** (all converted to a download failure; answer shorter than `Content-Length` counts as failed; cut-off JSON is retried).
- *Reviewer:* KEV date fields were only checked for presence; a replayed older list was accepted. **Fixed** (`dateReleased` must be a real time with time zone and not older than the saved copy; `dateAdded` must be a real date; duplicate IDs rejected; the 5% drop is measured against the highest count ever seen, so slow shrinking is caught).
- *Reviewer:* `status` could crash on a run file with a time without time zone, show "-1 hours ago", or pick the wrong "latest" run (file `…Z-2.json` sorted before `…Z.json`). **Fixed** (all three; a test found the sort bug).
- *Reviewer:* saved KEV file's fingerprint did not match the saved bytes. **Fixed** (data and fingerprint are in one file).
- *Auditor:* only port 443 should be allowed; one slow server could stall a run. **Fixed** (port check; 120-second limit for a whole download).
- *Auditor:* Windows device names (`CON`, `NUL`) as file names. **Fixed** (`osv-` prefix plus the shared safe path helper).
- *Not changed (accepted, as PLAN.md already says):* a local person who edits files in `cache/` can plant a fake saved record; fingerprints on every load were cut from v1 as "overkill". Honest limit: the cache protects against *mistakes*, not against a dishonest person on the same computer.
- *Not changed:* the tool still honours a proxy setting from the environment (HTTPS_PROXY); I left that as normal user configuration.
- *For Phase 3:* free text in OSV/KEV records (summaries, descriptions) is stored unchanged. It must never reach the AI; Part 4 must only use the validated IDs.

**How it connects:** this is the "eyes" of the tool. It brings in the facts; the matcher (next) decides what they mean.

---

## Piece 7 — Matcher `src/matcher.py` (Phase 2)

**What I built:** plain code that answers, for each component and each vulnerability OSV lists for it: **AFFECTED / NOT_AFFECTED / UNKNOWN**, with the rule that gave the answer — and whether the vulnerability is **actively exploited** (only if it is in the KEV list, or a human has written an evidence file `evidence/<CVE>.json` with a link and a date). Rules from PLAN.md: versions are never compared as text; PyPI uses PEP 503 names and the `packaging` library; Maven checks the exact-version list first, then compares plain numbers (a limit like `2.0-beta9` counts as "just below 2.0"), anything else is UNKNOWN; if OSV says "affected" but our own check disagrees the answer is UNKNOWN (never silently NOT_AFFECTED); withdrawn advisories are ignored; git-commit ranges give UNKNOWN. Actions: AFFECTED + exploited → report case; UNKNOWN + exploited → urgent human review; AFFECTED not exploited → recorded.

**The plan's known real cases, checked against the saved real data (all pass as tests)**
| Case | Result |
|---|---|
| log4j-core 2.14.1 + Log4Shell | AFFECTED, in KEV → report case |
| log4j-core 2.17.1 + Log4Shell (our own range check) | NOT_AFFECTED |
| log4j-core 2.0-beta9 + Log4Shell | AFFECTED (via the exact-version list) |
| log4j-core 2.15.0 | not affected by Log4Shell, **affected by CVE-2021-45046, which is in KEV** → report case |
| requests 2.30.0 + CVE-2023-32681 | AFFECTED, not in KEV → recorded, no report |
| requests 2.31.0 | NOT_AFFECTED (a git-commit range in the second advisory gives UNKNOWN there) |

I also compared the matcher with OSV on all 6 real batch answers (32 listed vulnerability/component pairs: 7 + 3 + 8 + 0 + 8 + 6): the matcher says AFFECTED for every one OSV lists — no disagreement.

**New words**
- *Rule* — the short name of the reason for an answer (e.g. `osv_exact_version_list`).
- *Range (introduced / fixed / last_affected)* — OSV's way of saying "affected from version A up to, but not including, B".
- *Alias* — another ID of the same vulnerability (the GitHub advisory number and the CVE number).
- *Evidence file* — a small file a human writes to say "this is exploited, here is my source and the date".
- *PEP 503* — Python's standard rule for treating `Foo_Bar` and `foo-bar` as the same package name.
- *Pre-release / local version* — `2.0rc1` is a test version before 2.0; `1.0+abc` is a company's own build of 1.0.

**Reviewer findings and what I did (all fixed unless noted)**
- *Auditor (high):* if the KEV download failed, "not in the list" silently became "not exploited" → an affected component would be only "recorded". **Fixed:** findings carry `exploited_known`; when KEV is not fresh and nothing proves exploitation, the action becomes **URGENT_HUMAN_REVIEW**. If a stale KEV copy does say exploited, it still counts.
- *Reviewer:* a vendor build `1.0+abc` of a vulnerable `1.0` was judged NOT_AFFECTED. **Fixed.**
- *Reviewer:* range events in the wrong order lost an earlier range. **Fixed** (events are sorted first).
- *Reviewer:* an empty range, a SEMVER range or an entry with no data gave NOT_AFFECTED ("silent safe"). **Fixed:** they give UNKNOWN (`no_usable_range` / `range_type_not_supported`).
- *Reviewer:* `pkg:npm/...` could match a PyPI record; a Maven purl without a group became the name "None:a". **Fixed** (UNKNOWN `unsupported_package`).
- *Reviewer:* a CVE written in lower case or listed only as `upstream` was missed. **Fixed.**
- *Auditor:* odd record shapes (a number instead of a list...) crashed the whole run; a text `versions` field was searched by substring. **Fixed:** wrong shapes are treated as empty/UNKNOWN; every record is evaluated in a safety net that emits UNKNOWN `record_malformed`.
- *Auditor:* evidence files accepted future dates and compact dates. **Fixed.**
- *Auditor (medium):* a hostile OSV record could list a KEV CVE as an *alias* of an unrelated advisory and forge "exploited". **Partly mitigated:** each finding says whether the CVE came from the record `id`, an `alias` or `upstream` (`exploited_cve_matched_on`), so a human can see. Honest limit: if OSV itself were compromised, the tool would believe it.
- *Reviewer note, kept on purpose:* `evaluate()` always tells the matcher "OSV listed this", so a listed vulnerability that our check rejects becomes UNKNOWN, never NOT_AFFECTED. This is the PLAN.md rule; the cost is more human review, e.g. a patched version that OSV still lists.
- *Auditor:* hostile text from OSV (`summary`, `details`) can never reach a finding — only validated IDs, fixed rule names and component fields. A test checks this.

**How it connects:** this is the "brain" of Part 3. Its output (a list of findings with an action) is what Phase 3 will turn into a report draft, and what `cra run` prints now.

---

## Piece 8 — `cra run`, `cra status` and the optional live test (Phase 2)

**What I built:** two new commands in `src/cli.py`.
- `python -m src run --sbom <file> --config <file>` reads the SBOM, downloads the public data, checks every component, prints the findings and saves the run in `runs/`. Exit codes: **0** complete and nothing to do, **1** RESULT INCOMPLETE or a human must look, **2** input rejected, **3** at least one *report case* (affected AND actively exploited). It prints "No exploited vulnerabilities found…" **only** when all sources are ok, every component was really checked and the SBOM had no warnings. It always prints "KEV is a floor, not a ceiling" and "Nothing was sent. A human decides what happens next." — there is no send function.
- `python -m src status` shows the last fully successful run, and warns loudly if it is more than 26 hours old, if the latest run was incomplete, if components could not be checked, or if it found report cases.
- An **optional live test** (`tests/test_live_optional.py`): skipped normally; with `CRA_LIVE_TEST=1` it talks to the real OSV.dev and CISA KEV. I ran it once: **2 passed** (real KEV downloaded and validated and contains Log4Shell; real OSV lists Log4Shell for log4j-core 2.14.1). That proves the real download code (certificate checks, no redirects, size/length checks) works against the real sites, not just against fakes.

**Example (fake internet serving the real saved data) for the demo product:** two REPORT CASES on log4j-core 2.14.1 — CVE-2021-44228 (Log4Shell) and CVE-2021-45046, both in KEV; `smartheat-firmware-core` flagged for a human (no purl); requests 2.30.0 recorded (affected, not in KEV); the run is marked RESULT INCOMPLETE because one component cannot be checked; exit code 3.

**New words**
- *Exit code* — see Piece 5.
- *Report case* — our name for "affected AND actively exploited": the situation where the 24-hour early warning may be due.
- *Safety net* — a catch-all that turns an unexpected error into a clear message instead of a crash.
- *Atomic write* — writing a file so you either get the whole new file or the old one, never half a file.

**Tests:** `tests/test_cli_run.py` (18) and `tests/test_status_and_run_safety.py` (29) plus changes to older tests. They cover: the Log4Shell report case, failed KEV (never "quiet recorded"), OSV 429 forever, a clean product getting the all-clear, evidence file, bad SBOM rejected before any download, second run downloads less, the 26-hour warning, damaged and hostile run files, terminal escape characters in saved files, unwritable folders.

**Reviewer findings and what I did**
- *Reviewer + auditor:* an unwritable `runs/` or `cache/` folder (or an unexpected error) ended in a raw traceback and exit 1; the report case would have been hidden. **Fixed:** findings are printed before saving; a failed save prints "RUN NOT SAVED"; report cases still give exit 3; unexpected errors print "RESULT INCOMPLETE (internal error: <type>)" without the error text (which could contain paths).
- *Reviewer + auditor:* `status` called an incomplete run "all sources ok" and let it reset the 26-hour clock; `status` ignored report cases. **Fixed:** every run now stores `complete`, `report_cases` and `needs_human`; a run without the `complete` flag never counts as complete; `status` warns about report cases, human-review findings and SBOM warnings.
- *Reviewer:* the exit code of `status` depended on the word "WARNING" in the text. **Fixed** (`status_summary` returns the answer separately).
- *Reviewer + auditor:* a damaged or hostile run file crashed `status`, and its text could contain terminal escape codes. **Fixed** (type checks everywhere; `printable()` replaces control characters; a run dated far in the future never counts as "all ok").
- *Auditor (low):* the temp file for saving had a fixed name (a symlink trick). **Fixed** (random exclusive temp file). Only the newest 1,000 run files are read.
- *Reviewer:* one test could never fail (a loop over an empty list). **Fixed** and made non-vacuous.
- *Not changed (accepted):* `--cache/--runs/--evidence` accept any folder path you type. Only file *names* inside are fixed and safe; you are trusted with your own folders. A symlinked folder in `cache/` could redirect writes, but that needs local write access.

**How it connects:** Phase 2 is now usable end to end: SBOM → public data → AFFECTED/UNKNOWN + exploited → findings and an honest status. Phase 3 will turn a report case into a draft text.

---

## End of Phase 2 — review meeting and secrets check

**Who met:** the same three AI reviewers as in Phase 1 (security architect, penetration tester, code reviewer), two rounds, plus the secrets and credential hygiene reviewer.

**Honest note about the penetration-tester review: it was NOT completed.** In round 1 the penetration-tester agent was stopped by a safety classifier while it was writing its first attack script. It ran nothing and confirmed no exploit; it only read the code and wrote down seven *hypotheses*. I did not try to push it through; instead I tested and fixed each hypothesis myself (see below). In round 2 it re-checked those seven points **by reading the code only (it ran nothing)** and called them closed or accepted. So the correct statement is: *the hypotheses of the penetration-tester agent were checked and fixed, but no real attack was run by that agent in Phase 2.* A real penetration test and the Strix scan are still open (**Strix scan pending**, no API budget — also see QUESTIONS.md #8).

**Round 1 — what they found**
- *Security architect:* (1) a crashed run left no record, so `status` kept showing an older good run — **must fix**; (2) a human evidence file that exists but is broken, and relative default folders (Task Scheduler starts programs in other folders), could silently turn "exploited" into "not exploited" — **must fix**; (3) the cache stored the full OSV text, which Phase 3 could inherit; (4) a forged alias could create a report case; (5) `status` is not tied to a product.
- *Code reviewer:* all Phase 2 deliverables met (376 tests then; PROGRESS numbers verified: 1,754 KEV entries, 17 OSV fixtures, 18 / 29 tests in the two CLI test files). Problems: NOT_AFFECTED never comes out of the real `run` pipeline (a listed vulnerability becomes UNKNOWN if our own check disagrees) — only the rule-level function gives NOT_AFFECTED, so docs must not say the tool "clears" a version; the per-package summary was dead code; evidence files left no audit trail; `news_watcher.py` is large.
- *Secrets reviewer:* **PASS** (details below).
- *Penetration tester:* seven hypotheses from reading the code (cache without integrity check; unchecked numbers in the saved KEV file; no limit on work per run; slow parsing of huge version lists; weak KEV check on a first run; `related` ids not used; planted run file).

**Round 2 — what I did**
- A failed or crashed run now saves a record (`complete: false`, `error: <type>`); `status` then shows RESULT INCOMPLETE instead of the older good run.
- Default folders are now absolute (next to the program) and printed; a missing evidence folder prints a note; an evidence file that exists but is unusable → "exploited unknown" → **URGENT HUMAN REVIEW** with the CVE listed; valid evidence leaves its link and date in the finding.
- All saved OSV and KEV copies keep only a fixed list of fields (IDs, dates, ranges, versions). Free text (`summary`, `details`, `references`...) is dropped; older full cache files are slimmed when loaded. A test shows the real record does contain free text and the saved copy does not.
- Limits: at most 500 vulnerabilities per component, 3,000 record downloads per run, 20,000 versions per list; a planted `max_count` is type-checked and clamped; the KEV list must have at least 1,000 entries. Every limit makes the result **incomplete** (never quietly "ok"). A list that had to be cut is marked `truncated`, and a truncated record can never give NOT_AFFECTED (rule `record_truncated`). Findings that could not be judged because data was missing are counted as `data_gaps` and make the run incomplete.
- `cra run` prints one answer per package ("if any version is AFFECTED, the package counts as AFFECTED"); the run record stores the product, the SBOM fingerprint and the folders.
- `status` now says in plain words that the 26-hour warning is **not** a guarantee for the 24-hour deadline.
- Verdicts: security architect **agrees**; code reviewer **agrees** (condition: write this section — done); penetration-tester agent: hypotheses closed or accepted (read-only check).

**Decisions left as they are (written down honestly)**
- **NOT_AFFECTED is a rule-level answer only.** `cra run` never clears a vulnerability that OSV listed: if our own check disagrees with OSV, the answer is UNKNOWN (human review), as PLAN.md demands. In the real data this means: in the demo run **no finding is NOT_AFFECTED**. The 32-pair comparison above shows that the matcher agrees with OSV on pairs OSV lists (recall); it does not measure false alarms. The README must not say the tool "clears" a version.
- *Cache and run files can be edited by anyone with write access to the project folder* (a planted record with `withdrawn`, or a planted run file) — accepted by PLAN.md section (b); fingerprints would only protect against mistakes. The README must say so.
- *`related` ids are not used for the KEV link* (a forged link would create a false report case). A vulnerability linked to a CVE only through `related` would not match KEV.
- *Alias link:* a KEV CVE linked only through an alias still gives a REPORT CASE (the real Log4Shell is linked this way), flagged "a human should confirm". **Phase 3 rule (to be tested then): the CVE id in a report must come from the KEV match / evidence file, never from advisory text.**
- *The 26-hour limit is not a guarantee for the 24-hour deadline* (QUESTIONS.md #5).
- *`news_watcher.py` is large (about 650 lines); status display and run history could move to their own file.* Not refactored now.
- *Hash-pinned dependencies, a lockfile and `pip-audit` are not used.* The README must not claim supply-chain hardening.
- *One test is skipped on this computer:* the symlink test (this Windows account may not create symlinks), so "a symlink that points outside is refused" is **not** proven by a test here. Two more tests are skipped on purpose (the optional live tests).

**Secrets check #2 (secrets and credential hygiene reviewer): PASS.** No keys, passwords or tokens in the working files or in the 16 commits (checked before the last Phase 2 commits; the later changes added no secrets). `.env` does not exist and is ignored; `.env.example` holds only the placeholder; `cases/`, `cache/`, `runs/`, `*.pem`, `*.key` and the local settings file are ignored. The only "password" text is public advisory text inside saved fixtures. `gitleaks` itself is not installed here, so this was a pattern search (the GitHub scan will be the real one). The only environment variable read by any code is `CRA_LIVE_TEST` (in the optional live test).

**Tests at the end of Phase 2:** **407 passed, 3 skipped, 0 failed** (410 collected). Per file: `test_sbom_reader` 103, `test_matcher` 100, `test_news_watcher` 84, `test_phase2_hardening` 34, `test_safe_paths` 30, `test_status_and_run_safety` 29, `test_cli_run` 18, `test_cli` 10, `test_live_optional` 2. The optional live test passed when run once on 2026-10-21 against the real sites (2 passed).

**How it connects:** Phases 1 and 2 give the tool its "eyes and brain": a safe SBOM reader, careful downloads, and a matcher that says AFFECTED / NOT_AFFECTED / UNKNOWN and whether it is actively exploited — and says "RESULT INCOMPLETE" instead of guessing. Phase 3 (not started, as ordered) will turn a *report case* into German and English text.

---

## Outside check: Bandit (2026-10-25)

**What Bandit is:** a free tool that reads Python code (without running it) and warns about patterns that are often unsafe, for example running shell commands, `eval`, weak hashes, hard-coded passwords or unsafe XML/pickle use. It is an outside check on top of our own reviews.

**What was run:** Bandit 1.9.4 (now pinned in `requirements-dev.txt`) with `.venv\Scripts\python -m bandit -r src -f txt -o reports\bandit-2026-10-25.txt`, on Python 3.14.7. Full report: `reports/bandit-2026-10-25.txt`.

**Real numbers from the report:**
- Code scanned: 1,421 lines in `src/`. Lines skipped with `#nosec`: 0. Issues switched off on purpose: 0.
- Issues by severity: Undefined 0, Low 0, Medium 0, High 0.
- Issues by confidence: Undefined 0, Low 0, Medium 0, High 0.
- Result text: "No issues identified." Files skipped: 0.

**Assessment:** there are no findings, so there is nothing to call a real risk or a false alarm, and nothing was fixed. This is a narrow result. Bandit only checks `src/` for known risky Python patterns. It does not check `tests/`, the logic of the matcher, the dependencies (that would need a tool such as `pip-audit`, which we do not use), or how the program behaves when run. It does not replace the reviews and the penetration-tester check already done. Nothing here changes the earlier statements in this file.

---

## Outside check: Strix AI penetration test (2026-10-25)

**What Strix is:** a tool where an AI plays the attacker. It reads the code, tries hostile inputs and reports what it could break. It is an outside check on top of our own reviews.

**What was run (real numbers from `reports/strix-2026-10-25/`):** Strix v1.7.0 with Claude Haiku 5.5, quick mode. About 100.7 million tokens (100,849,428 in `run.json`, 456 requests), cost $7.29. Scope: the runtime code in `src/`. Full report: `reports/strix-2026-10-25/penetration_test_report.md`.

**Result: 11 findings: 0 Critical, 0 High, 2 Medium, 9 Low.** The tool runs locally and opens no network port; the real risk is a *wrong regulatory answer* (a reportable case shown as "clean"), not a break-in.

| ID | Severity | In one simple sentence |
|---|---|---|
| vuln-0004 | Medium | A Maven component written with slashes or capital letters was accepted as fine, OSV found nothing for that spelling, and a Log4Shell component looked clean. |
| vuln-0007 | Medium | A KEV list with known-exploited CVEs quietly removed was still accepted as complete. |
| vuln-0001 | Low | A fake run file planted in the runs folder can make `status` say everything is fine. |
| vuln-0002 | Low | `status` loads every run file into memory with no total size limit. |
| vuln-0005 | Low | When a fix and a re-introduction share one version number, the range is sorted wrongly and an affected version looks unaffected. |
| vuln-0006 | Low | If OSV gave no answer for a component, it was still marked "we know it is not exploited". |
| vuln-0008 | Low | One KEV answer dated in the future would freeze the saved copy so real updates are refused. |
| vuln-0009 | Low | The 120-second download limit was only checked between reads, so a slowly dripping server could stall a run. |
| vuln-0011 | Low | An OSV id ending in a dot crashed the whole run. |
| vuln-0012 | Low | Two runs finishing in the same second could overwrite each other's record. |
| vuln-0013 | Low | A run record over 20 MB was silently skipped by `status`, which then showed an older clean run. |

**Controls Strix confirmed as working:** SBOM limits (depth, size, duplicate keys, NaN/Infinity, component count) held under about 30,000 fuzzed components and 3,000 file mutations; terminal-escape injection is blocked; path containment holds (OSV ids, symlinks, evidence ids); redirects are refused, the host list and TLS checks hold; cache keys are hashed and cache poisoning by purl was not reproduced.

**Open items Strix did not file (need maintainer decisions, see QUESTIONS.md):** batch answers are matched to components by position (only the count is checked); OSV `limit` events are ignored; PEP 440 local-label stripping; KEV link through `upstream`; urgency of components without a purl.

**Limits of this check (from the report):** no web search, so the pinned dependencies were not checked against advisory databases; the KEV attack assumes an on-path attacker with a trusted certificate and was simulated, not seen on the real network; fixes were tested only in working copies, the repository was not changed.

**Systemic theme:** in several places the tool treated "no answer" or "well-formed" as proof that a check was *complete*. The fix direction is: uncertain means UNKNOWN or INCOMPLETE, never "safe".

**How it connects:** Part C of this work fixes these findings one by one, each with a test that fails first.

---

## Fixing the Strix findings (Part C)

### Fix vuln-0004 — odd Maven spellings looked "clean" (Medium)
- **What was wrong:** a Maven component written as `pkg:maven/org/apache/logging/log4j/log4j-core@2.14.1` (slashes) or with capital letters was accepted as fine. OSV (the vulnerability database) does not know those spellings, found nothing, and the tool said "no problems" for a Log4Shell component.
- **The fix:** in `src/sbom_reader.py` such a component now becomes UNKNOWN ("a human must look") with a clear reason. Slashes in the group, capital letters, and names that cannot exist (`@`, `:`, `~`, trailing dots) are refused. A purl that needed `%` escapes when rebuilt is refused too. Trade-off: real Maven names with capitals (like `xercesImpl`) now need a human look. That is the safe side.
- **Tests:** 4 new tests for the slash and capital-letter spellings failed on the old code (4 failed) and pass now. The old test that expected `a//b` to be OK was changed to expect UNKNOWN. After the security reviewer found more odd spellings, I added 5 more tests together with the stricter check (these were not run on the old code first). Full suite: **415 passed, 3 skipped, 0 failed.**
- **Reviews:** code reviewer: nothing blocking. Security auditor: found the `@`/`:`/`~`/trailing-dot gaps, fixed. Not fixed: a version in capitals (`1.0-RC1`) is still accepted; unclear how OSV treats it, written to QUESTIONS.md.

### Fix vuln-0007 — a KEV list with exploited CVEs quietly removed was accepted (Medium)
- **What was wrong:** KEV is the US list of vulnerabilities known to be exploited. The tool only checked that the new list was not more than 5% shorter. Someone in the middle of the network connection could remove two entries (like Log4Shell) and the tool still said "KEV ok", so a REPORT CASE became a plain RECORD.
- **The fix (`src/news_watcher.py`):** if the new list is missing any CVE id that the saved copy had, KEV becomes **stale**, the run is **INCOMPLETE**, the old saved copy is kept (not overwritten), and the missing ids are printed so a human can check. CISA may remove entries legitimately, so nothing is silently accepted or rejected. After the human check, delete `cache/kev/kev-saved.json` to accept the new list. Lists that only add ids are still accepted.
- **Tests:** 3 new tests failed on the old code (3 failed, 1 guard test passed) and pass now; 1 old test ("a drop under 5% is accepted") was changed on purpose; 1 extra end-to-end test (run is incomplete). Full suite: **420 passed, 3 skipped, 0 failed.**
- **Reviews:** code reviewer and security auditor: no blocking problems; I fixed a misleading message ("download failed"). Still open (QUESTIONS.md S2, S3): replay of the old list with a newer date and the first run without a saved copy are not stopped (needs a signature or pinned hash); a damaged saved file loses the baseline; a legitimate CISA removal keeps KEV stale until a human deletes the saved file.

### Fix vuln-0006 — "no answer from OSV" was recorded as "known not exploited" (Low)
- **What was wrong:** when OSV gave no answer for a component (or its details could not be loaded or read) and the KEV list was fresh, the tool still wrote "we know whether it is exploited: not exploited". It had never compared anything with KEV, so the finding went to normal instead of urgent human review.
- **The fix (`src/matcher.py`, one line each on three paths, plus the CLI message in `src/cli.py`):** these findings now say "exploited status NOT known" and become **URGENT HUMAN REVIEW**.
- **Tests:** 3 new tests, 3 failed on the old code and pass now (the no-answer, details-missing and malformed-record paths). Full suite: **422 passed, 3 skipped, 0 failed.**
- **Reviews:** code reviewer: nothing. Security auditor: the three paths are right; it named two more places, which are **policy decisions I did not make** (QUESTIONS.md S4, S5): components without a purl, and advisories that list no CVE id at all.

### Fix vuln-0005 — a fix and a re-introduction at the same version hid an affected version (Low)
- **What was wrong:** OSV describes affected versions as events like "introduced 0", "fixed 2.0", "introduced 2.0" (fixed, then broken again). The matcher sorted ties so that every "introduced" came before every "fixed" at the same version, which swallowed the re-introduction. Version 2.5 then looked NOT affected.
- **The fix (`src/matcher.py`, `_intervals`):** events at the same version now keep the order they were written in. If the order is ambiguous (an "introduced X" written before a "fixed X" inside an open range, which could be a re-ordered list), the answer is UNKNOWN, not "safe".
- **Tests:** 4 new tests; 3 failed on the old code (maven, pypi, reversed tie) and pass now; the 4th (ambiguous tie) was added with the extra safety rule, and would have failed on the old code too (it said NOT_AFFECTED). Full suite: **426 passed, 3 skipped, 0 failed.**
- **Reviews:** code reviewer: nothing. Security auditor tried every order of 2-5 events and found no wrong "safe" answer except the ambiguous tie, which I made UNKNOWN. OSV does not define the order of tied events, so this is a design choice noted here.

### Fix vuln-0013 — a run record that was too big (or damaged) was skipped by `status` (Low)
- **What was wrong:** `cra status` read up to 20 MB per run file and silently skipped any file it could not read. If the newest run (maybe one with a REPORT CASE) was skipped, `status` showed the older clean run as "the latest" and exited 0.
- **The fix (`src/news_watcher.py`, `load_runs`):** a run file that is too big, damaged, not a JSON object, or has no readable `finished_at` with a time zone is no longer skipped. It stands in as a **failed, INCOMPLETE run** (time = the file's modification time), so `status` prints RESULT INCOMPLETE and exits 1. Folders or broken links named `*.json` are still ignored.
- **Tests:** 6 tests failed on the old code and pass now (oversized, damaged, and 4 shapes of unreadable file). One old test ("a damaged run file is ignored") was changed on purpose: it now expects INCOMPLETE. Full suite: **431 passed, 3 skipped, 0 failed.**
- **Reviews:** code reviewer: no bug in the first version. The security auditor and reviewer both said damaged files were still skipped; I generalized the fix as they suggested (this last step was **not** reviewed again). Still open (QUESTIONS.md S6): a file's modification time can be faked, and more than 1000 run files are cut by file name, not by time.

### Fix vuln-0001 (simple safe part only) — a planted run file could make `status` say "all fine" (Low)
- **What was wrong:** anyone who could put a file in the `runs/` folder could add a fake "healthy" run record with a newer time. `cra status` then showed "Latest run: all sources ok." and hid a real REPORT CASE.
- **The simple safe part I did (`src/news_watcher.py`):** `cra run` now adds a **seal** (a SHA-256 fingerprint of the record's content) to every run record. `status` checks it: a record with a missing or wrong seal counts as a **failed, INCOMPLETE run** (it keeps its own time, so it still shows up as the latest and cannot hide behind older runs). This stops fake files and edits made by hand.
- **What it does NOT do:** the seal is not a secret. Someone who reads the code can compute it, so a determined local attacker is not stopped. A real fix needs a key (signing) and a decision on where to keep it. That is a design decision, so I did **not** make it: QUESTIONS.md S7. PLAN.md already lists a local writer as an accepted risk; the README must say so.
- **Side effect:** run records saved before this change have no seal. `status` shows them as "not verified" until the next `cra run` writes a sealed record.
- **Tests:** 2 new tests failed on the old code and pass now (planted healthy file; edited record); 1 guard test (a normal run still shows "all sources ok") passed before and after. Full suite: **434 passed, 3 skipped, 0 failed.**
- **Reviews:** code reviewer and security auditor: no bypass beyond the known limit. Notes: a far-future unsealed file keeps `status` warning until deleted (fails closed).

### Fix vuln-0002 — `status` loaded every run file into memory (Low)
- **What was wrong:** `cra status` read up to 1000 run files (each up to 20 MB) and kept all of them in memory, although it only needs two: the newest run and the newest complete run. A folder full of big files could use up the computer's memory.
- **The fix (`src/news_watcher.py`, `load_runs`):** files are read one at a time and only those two records are kept. There is now a **total size budget** (`MAX_RUN_TOTAL_BYTES`, 200 MB). If the folder is over the budget, `status` adds a failed stand-in dated "now" and prints RESULT INCOMPLETE ("over the read budget"), so a record that was not read can never hide behind an older clean run. A file whose size cannot be measured counts as a big file.
- **Changed on purpose:** the old rule "read only the newest 1000 file names" is gone. Both reviewers showed it silently dropped files chosen by *name*; making that an error would have turned `status` permanently INCOMPLETE after about 5 months of normal runs (one run every 4 hours). The byte budget now bounds the work instead. Consequence: after many years of runs the folder may exceed 200 MB, and a human then has to archive old run files (QUESTIONS.md S8).
- **Tests:** 2 new tests failed on the old code and pass now (only 2 records kept; over budget is incomplete). 2 old tests changed on purpose (they expected all runs to be returned / a file-count cut-off). Full suite: **436 passed, 3 skipped, 0 failed.**
- **Reviews:** code reviewer: no blocker. Security auditor: no memory or time problem; its 2 findings (file-count cut-off, un-measurable file size) were handled as described. The final cap removal was not reviewed again.

### Fix vuln-0008 — a KEV list dated in the future froze the saved copy (Low)
- **What was wrong:** the tool accepted any well-formed `dateReleased` on the KEV list, even one dated years ahead. After one such answer was saved, every later genuine list looked "older than the saved copy" and was refused as a possible replay, so new exploited vulnerabilities were never picked up until someone deleted the cache file.
- **The fix (`src/news_watcher.py`):** a KEV list dated more than 1 day after the computer's time is rejected ("dateReleased is in the future"): KEV becomes stale and the old copy is kept. The same check applies when the saved copy is loaded, so a copy that was already saved with a future date is thrown away and the next genuine list is accepted again.
- **Tests:** 3 new tests failed on the old code and pass now (future list rejected and updates still work afterwards; saved future copy discarded; a list a few hours ahead is still accepted). Full suite: **439 passed, 3 skipped, 0 failed.**
- **Reviews:** code reviewer and security auditor found no bypass but both pointed to the same trade-off (QUESTIONS.md S9): if the computer clock runs more than 1 day *behind*, a valid saved copy is also discarded, which switches off the replay and count checks for that run (the result stays fail-closed: KEV is not "ok" without a baseline-free genuine list, and `status` already warns about a wrong clock). Also still possible: a response dated up to 1 day ahead can freeze updates for up to a day.

### Fix vuln-0009 — a slowly dripping server could stall a download (Low)
- **What was wrong:** `http_fetch` has a 120-second limit for one download, but it only looked at the clock between reads. A read waited until 64 KB had arrived, so a server that sends one byte every few seconds kept one read open for as long as it liked, and a scheduled `cra run` could hang.
- **The fix (`src/news_watcher.py`):** the body is now read with `read1`, which returns after one network read, so the time limit is checked after every small chunk. The worst case is the limit plus one 30-second read timeout.
- **Test:** 1 new test uses a real socket that drips one byte every 0.05 s for about 10 seconds with a 0.3-second limit (no fake clock). It failed on the old code (it waited the full 10 seconds) and passes now (stops in under 2 seconds). Full suite: **440 passed, 3 skipped, 0 failed.**
- **Reviews:** code reviewer: no problems. Security auditor: confirms the body drip is fixed, but says the *whole run* is still poorly bounded: a slow server while connecting or sending headers, 4 tries per download, and up to 3000 detail downloads. That is a bigger design change (a run-wide time budget), so I did not do it: QUESTIONS.md S10.
