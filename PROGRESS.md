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
