# Open Questions for Fares

Questions that came up while building on autopilot. Each one has a **temporary** safe choice that was used so work could continue. Please answer or change them. Rows marked **DECIDED** have been answered by Fares; the "temporary choice" column then only shows what was used before the decision.

| # | Question | Temporary choice used | Status |
|---|---|---|---|
| 1 | Should an SBOM with no `components` at all be rejected, or accepted with a warning? | Accepted, but the reader returns a loud warning ("SBOM has no components") so it can never look like "all clear". | temporary |
| 2 | Pin the two GitHub Actions in `.github/workflows/gitleaks.yml` (`checkout@v4`, `gitleaks-action@v2`) to full commit codes? | Left on version tags for now: I may only use the network for OSV/KEV, so I could not look up the real commit codes, and I will not invent them. | **DECIDED by Fares (2026-10-21):** Yes, pin all GitHub Actions to exact commit SHAs before the first push to GitHub. |
| 3 | Which exit code should `cra check-sbom` give when some components are UNKNOWN? | 1 ("a human must look"); 0 = all fine, 2 = file rejected. | temporary |
| 4 | When all sources are fine but some components are UNKNOWN (e.g. the firmware without a purl), what should the final message say? | It says "no exploited vulnerabilities found among the checked components" AND lists the UNKNOWN components loudly as "could NOT be checked". It never says plain "all clear". | temporary |
| 5 | `cra status` warns after 26 hours (the PLAN.md number) and the plan says "daily". A single missed daily run therefore means the first warning comes late in the 24-hour reporting window. Should `cra run` be scheduled every 4-6 hours, with the warning threshold set to about 1.5 times that? | Kept the plan's daily run and 26 hours. Recommendation: schedule every 4-6 hours in the Windows Task Scheduler. | **DECIDED by Fares (2026-10-21):** Yes, run `cra run` every 4 hours with Windows Task Scheduler (to be set up in Phase 4). |
| 6 | One complete run of product A currently resets the "last successful run" clock for product B (all runs share one `runs/` folder). Each run now stores the product name and the SBOM fingerprint, but `cra status` does not group by product yet. | Left for Phase 4; use one `runs/` folder per product until then. | temporary (before Phase 4) |
| 7 | When the link from a vulnerability to the KEV list rests only on an alias (the OSV advisory lists the CVE number as an alias, which is how real Log4Shell is linked), should it still be a REPORT CASE? | Yes, still a report case, but the finding says `exploited_cve_matched_on: alias` and the output says "a human should confirm". Phase 3 must take the CVE id from the KEV match, never from advisory text. | temporary |
| 8 | The Strix scan and a complete penetration-tester review could not be done for Phase 1/2 (no API budget; the penetration-tester agent was stopped by a safety classifier in Phase 2 round 1 before it ran anything). | I checked its written hypotheses myself with tests and recorded this honestly in PROGRESS.md. A real Strix scan and a fresh pen-test are still open. | **DECIDED by Fares (2026-10-21):** Use a free Google Gemini API key for Strix scans (quick mode). The Strix scans for Phase 1 and 2 will run once Fares has the key; until then they stay pending. |
| 9 | The KEV sanity check now insists on at least 1,000 entries (the real list has 1,754). If CISA ever legitimately cleans the list below that, the tool would call every download "failed" and fall back to the saved copy. | Kept 1,000 as the safe side. | temporary |

## Later improvements (after Phase 3)

Ideas Fares noted on 2026-10-21. Nothing here is built yet; do not start before Phase 3 is finished.

1. **Group findings by CVE.** The same vulnerability often appears under different IDs (for example a GHSA number and a PYSEC number). Show it once, listing all its IDs, instead of once per ID.
2. **Fewer "a human should confirm" notes (avoid alarm fatigue).** Show that note only for really uncertain CVE links (for example a link that rests only on `upstream`), not for the normal case where a GHSA advisory lists the CVE as an alias. (This changes the temporary choice of question #7.)
3. **User notice draft (from the CRA legal check, 2026-10-25).** Art. 14(8) requires informing impacted users, where appropriate in a machine-readable format. Add a draft of this user notice, approved by a human like every other text. See PLAN.md section (g).

## Decisions on security scanning (2026-10-25)

- **Strix with free Gemini failed:** the free tier allows only 20 requests per day per model, far too few for an AI pentest. **Decision:** run Bandit now (free), Strix with Claude Haiku in November.

## Questions from the Strix fixes (2026-10-25, autopilot)

| # | Question | Temporary (safe) choice used |
|---|---|---|
| S1 | Maven versions in capital letters (`1.0-RC1`): does OSV match them case-sensitively? Should they be UNKNOWN like capital group/artifact names? | Still accepted as OK (not verified offline). |
| S2 | KEV removal policy (vuln-0007): CISA may remove entries on purpose. Today any dropped id makes KEV stale until a human deletes `cache/kev/kev-saved.json`. Should there be a command to accept a reviewed removal? | Stale + INCOMPLETE + ids printed; saved copy kept. |
| S3 | KEV authenticity (vuln-0007): a replay of the old list with a newer date, the first run (no baseline), a damaged saved file (baseline lost) and changed `dateAdded` values are not detected. Needs a signature, a pinned hash or a second source. Which one? | Not decided; documented as a known limit. |
| S4 | Components without a purl (UNKNOWN) still count as "exploited status known" when KEV is fresh, so they get HUMAN_REVIEW, not URGENT. Should they be urgent too? (Strix vuln-0006 open item.) | Unchanged (HUMAN_REVIEW). The run is INCOMPLETE and exits 1 anyway. |
| S5 | An AFFECTED advisory that lists no CVE id at all (GHSA-only) cannot be compared with KEV or evidence files. Today that counts as "known not exploited" (RECORD). Should it be urgent human review? | Unchanged (RECORD). |
| S6 | `status` takes the time of an unreadable run file from its modification time (can be faked by a local writer) and reads only the last 1000 file names (sorted by name, not time). Should unreadable files use the later of file time and the time in the file name, and should the 1000-file cap go? | Unchanged; a local writer is already an accepted risk (S7 / vuln-0001). |
| S7 | Run-record integrity (vuln-0001): the seal is only a fingerprint, not a signature. Should run records be signed with a key (where is the key kept?), or is "a local writer is trusted" (PLAN.md section (b)) enough, documented in the README? | Unkeyed seal + "unsealed or changed = INCOMPLETE". Old unsealed records show as "not verified". |
