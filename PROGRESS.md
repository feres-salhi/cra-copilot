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
