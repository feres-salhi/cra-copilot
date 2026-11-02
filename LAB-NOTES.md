# Lab Notes

A dated, honest diary of building CRA Copilot. It is the diary of Fares (a student at TU Darmstadt) working with Claude Code and a team of AI helper agents. Where something went wrong, there is a "What I learned" line.

Note: the README has the results. This file has the story, including the mistakes.

## 2026-10-21: Idea, rulebook, design and Phases 1 and 2

**Research and idea.** I looked at the EU Cyber Resilience Act, Article 14. A manufacturer must send an early warning within 24 hours when a vulnerability in their product is actively exploited. For a small company that is a real problem, so I decided to build a helper tool.

**Rulebook and setup.** I wrote the project rulebook (`CLAUDE.md`). I set up Claude Code with agent teams enabled and in ask-first mode, so it asks before it acts. I created the Python virtual environment, set up pytest, and made a `.gitignore` that blocks private folders and key files. I added a `.env.example` that holds only a placeholder, no real key.

**Design meeting.** An agent team held a design meeting. The result is `PLAN.md` (screenshots 01a and 01b). I recorded my design decisions.

**Fake demo product.** I made a fake demo product, so that no real company's data is ever used.

**Phase 1: SBOM reader.** The SBOM reader treats the file as hostile. Its limits are 10 MB file size, depth 32, 5,000 components, and duplicate keys are rejected. A review meeting led to these fixes:

- purl qualifiers are handled.
- A `safe_join` path helper was added.
- An empty SBOM now counts as INCOMPLETE.

The secrets check passed.

**Phase 2: news watcher and matcher.** The news watcher reads OSV and the CISA KEV list. The matcher compares them with the components. I tested with saved real data; the KEV list had 1,754 entries. Surprises:

- CVE-2021-45046 IS in KEV.
- A test found a bug: OSV "modified" times have 6 or 9 decimal places.
- Even `log4j-core 2.17.1` has newer real OSV vulnerabilities.

**First live run.** The first live run with Log4Shell worked (screenshot 03). The tests showed 407 passed (screenshot 02).

**Mistake: the penetration-tester agent was stopped.** In Phase 2, round 1, the penetration-tester agent was stopped by a safety classifier before it ran anything. I checked its written hypotheses myself with tests. This was a limit of the process, not something I hid.

*What I learned:* record such limits honestly. A review that did not run is not a review that passed.

**Decisions.** I decided to pin GitHub Actions, to run the check every 4 hours, and to use Strix with a free Gemini key.

## 2026-10-25: Legal check, Bandit and Strix

**Legal check.** I added a CRA legal check to `PLAN.md`. Article 14 applies from 11 September 2026. I also noted the idea of the user notice in Article 14(8).

**Bandit.** Bandit found 0 issues (screenshot 04).

**Strix, first attempt.** Strix with the free Gemini key failed. The free tier allows only 20 requests per day per model.

*What I learned:* check the limits of a free tier before planning a long job on it.

**Strix, second attempt.** I switched to Claude Haiku 5.5. The run took about 22 minutes (15:27 to 15:49 UTC), used 100.7 million tokens and cost $7.29. By my own account, the cost was much higher than I had estimated; the files only record the actual cost.

*What I learned:* estimate the cost of an AI scan before starting it.

**Findings.** Strix found 11 findings (screenshots 05a and 05b). I fixed them one by one. Each fix got a failing test first, two reviewers, and its own commit. The tests ended at 445 passed, 3 skipped.

*What I learned:* "no answer" must never look like "nothing found". Many of the findings were this same mistake in different places.

## 2026-10-26: Decisions and Phase 3

**Decisions.** I decided:

- S2: build `kev accept-removals`.
- S3: no check of KEV authenticity. It is a known limit.
- S7: no signing of run records.

Screenshot 06 shows the tests after the Strix fixes.

**Phase 3: the report text.** I did these steps:

- Renamed REPORT CASE to POSSIBLE REPORT CASE, because the tool only finds a possibility. A human decides.
- Built the facts builder.
- Built the fixed German and English template.
- Built the fact checker.
- Put the report writer behind one function.
- Built the `.env` reader.
- Built `preview-report`.

**The switch from word lists to approved sentences.** First the AI wrote free text and a forbidden-word list checked it. The security auditor beat that list. Then I tried an allowed-word list. The auditor and the penetration tester beat that too: a sentence made only of allowed words can still be false. A team meeting agreed on a new design. The AI may only choose among approved whole sentences that a human wrote.

*What I learned:* code cannot judge the meaning of free text. Do not make the AI write what code must check. Let it choose from a fixed list.

The tests ended at 977 passed, 5 skipped.

## Undated: the `.env` file was overwritten

This happened between the Phase 3 entry and 2026-11-02. This is my own account. The project files do not record the date.

I typed notes into a Notepad tab that was still open on my `.env` file, and the file was overwritten by those notes.

*What I learned:* never keep a secret file open in an editor.

## 2026-11-02: A very long day (33 commits)

**Live Gemini test.** The first real Gemini call passed: mode `ai`, fact check PASS (screenshot 07). Later calls got HTTP 429, and the tool used the fixed fallback text, as designed.

**Mistake: the API key was printed.** When the live test failed, pytest printed the full Gemini API key in a traceback, because tracebacks show plain-text variables. I noticed it. I treated the key as burned and rotated it. The fix:

- The key now lives in a `Secret` box that prints as `***`.
- `http_fetch` drops inner error details.
- Tests print only the error type and status.
- pytest uses short tracebacks.

Reviewers found a second leak path in the first fix, which I also fixed. There are 10 regression tests (screenshot 08). The tests ended at 995 passed, 5 skipped.

*What I learned:* secrets leak through error messages, not only through files.

**Mistake: a stray environment variable.** The shell variable `CRA_LIVE_AI=1` was set. Because of it, the bare pytest runs of reviewing subagents called real Gemini twice during the key fix (HTTP 429 and 503). It happened once more during the Phase 4 review (429). The key was not printed.

*What I learned:* tests must never make real network or AI calls by accident. Always unset that variable.

**Phase 4: cases and approval.** I built these parts:

- Cases.
- `draft`: the typed awareness time is checked against what the tool saw.
- Re-derive "affected" from the SBOM.
- `approve`: 3 typed answers, `approvals.log`, sha256 fingerprints (screenshot 09).
- `close`.
- A run that ends with a list of open cases and deadlines.
- The schedule scripts. The assistant did not run them.

A team reviewed it in 2 rounds. Two serious items were fixed. The secrets check passed (56 commits at that time). The tests ended at 1,232 passed.

**Schedule.** The assistant wrote the schedule scripts (every 4 hours) but never ran them. Screenshot 10 shows the scheduled task on this computer, with LastTaskResult 3 (an exit code of `cra run`).

**Seven improvements:**

1. The summary no longer says "draft".
2. Commands work on this computer.
3. `status` shows two clocks.
4. Times use ISO 8601.
5. The same vulnerability is grouped.
6. The confirm note appears only for upstream links.
7. `docs/run-record-format.md` was written.

The tests ended at 1,319 passed.

**Alerts and close.** I added alerts (Q1): rules, a toast, `alerts.log`, `alerts --test` and `--list`, and `--no-alerts`. I also added `close` (Q5). The tests ended at 1,450 passed (screenshot 11).

**Honest note: the toast.** The assistant never showed a real toast itself. The way to check it is `alerts --test` on this computer (screenshot 11 shows an alert).

**Publish cleanup.** To get ready for GitHub I did these steps:

- Pinned GitHub Actions to commit SHAs.
- Added the MIT LICENSE.
- Untracked `strix.log` and `.state`.
- Rewrote the git history, with a local backup branch `backup-before-rewrite`. It must never be pushed.

All 77 commits are now authored by "Fares Salhi" with the GitHub noreply address. The Strix log and state files are gone from history.

**Mistake: a step left undone.** At first, cleanup step 7 was left undone, because the work order gave no noreply address and the assistant will not guess one. It was done in the next step (the history rewrite).

*What I learned:* an assistant that stops and asks is better than one that guesses. Put every needed detail in the work order.

**Accepted items.** A third-party e-mail address in a public advisory test fixture was accepted by me. My user folder name in screenshots was accepted too.

Nothing has been pushed yet.
