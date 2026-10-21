# Progress Log

*(A short summary for Fares will be written at the very top when the autopilot work is finished.)*

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
