# Security Penetration Test Report

**Generated:** 2026-10-25 22:08:45 UTC

# Executive Summary

An authorized white-box assessment of the CRA Copilot command-line tool identified **11 vulnerabilities**: **2 Medium** and **9 Low**. No Critical or High issues were found. The tool runs locally, opens no network listener, and has no code-execution sinks on untrusted input, so the realistic risk is incorrect regulatory outcomes rather than system compromise.

**Overall risk posture:** Moderate. The main risk is that the tool can report a vulnerable, actively exploited component as clean or downgraded, which would cause a manufacturer to miss the 24-hour early-warning deadline under the EU Cyber Resilience Act.

**Key findings**
- **Maven purl spelling bypass (Medium, 5.5):** a supplier SBOM that uses a slash-separated or upper-case Maven coordinate is accepted as clean. The KEV-listed log4j-core 2.14.1 then produces zero findings and exit code 0 instead of a REPORT CASE.
- **KEV list substitution (Medium, 5.9):** an on-path attacker with a trusted TLS position can remove known-exploited CVEs from the CISA KEV download. The run is still marked complete and KEV "ok", which downgrades a REPORT CASE to RECORD.
- **Integrity and availability of the status verdict (Low):** a planted run record can make `status` report a healthy run, and oversized run records are silently skipped.
- **Matcher correctness (Low):** same-version range ordering can hide a reintroduced affected version, and unchecked components can be recorded as known not exploited.
- **Feed and cache robustness (Low):** a future-dated KEV response freezes later updates, the download deadline is not enforced during slow reads, a trailing-dot OSV id aborts the run, and concurrent run saves can overwrite each other.

**Business impact:** Both Medium findings can cause a reportable event to be silently missed, which carries regulatory exposure. Nothing reviewed exposes data, enables remote access, or executes code.

**Remediation theme:** the tool treats structural validity and an absent answer as proof of completeness. Fail-closed handling for ambiguous component identity, feed completeness, and run integrity would close most of the findings.

# Methodology

Engagement type: white-box, local source code with dynamic validation. Scope: the CRA Copilot Python CLI (`src/` runtime modules: `cli.py`, `sbom_reader.py`, `news_watcher.py`, `matcher.py`, `safe_paths.py`). Tests, demo data, and CI workflow files were treated as non-runtime.

**Approach**
- A shared threat model was derived first. Attacker-reachable inputs were identified as the SBOM file, the remote OSV and KEV feed responses, and locally written run and cache records. The operator running the CLI was treated as trusted.
- Static triage covered semgrep, gitleaks, trufflehog, trivy filesystem scanning, and an ast-grep structural pass over the runtime modules. Triage produced no confirmed static findings.
- Dynamic validation ran against copies of the repository. Hostile SBOMs, feed responses (served over a locally trusted TLS endpoint with the fetch injection points), evidence files, and run records were exercised through the real CLI and the module functions. The existing test suite was used as a baseline and after each patch.
- Each candidate was assessed for input handling, path containment, redirect and size controls, decompression, cache poisoning, atomic writes, terminal-escape injection, information disclosure, range logic, and KEV decision logic, and each was closed as confirmed or with a named control.

**Limits**
- Web search was not configured for this scan, so known-CVE checks for the pinned dependencies (`packageurl-python` 0.17.6 and `packaging` 26.3) could not be confirmed against advisory databases. Trivy's offline database reported no vulnerabilities.
- The KEV substitution finding assumes an attacker with a TLS-trusted interception position. This was simulated, not observed on the live network.
- Fixes were verified in working copies. The user's repository was not modified.

# Technical Analysis

**Severity model:** CVSS 3.1 scores reflect the demonstrated attacker position. The tool has no network service, so local-file and on-path feed attacks are rated accordingly.

**Medium**
1. **Maven purl spelling bypass clears exploited components** (vuln-0004, 5.5). Slash-separated and upper-case Maven coordinates are accepted as canonical. OSV matches neither, so an affected and KEV-listed component is reported clean with exit 0. Root cause: `sbom_reader.py` accepts non-canonical identity, and an absent advisory answer is treated as a clean result.
2. **Substituted KEV list accepted as complete** (vuln-0007, 5.9). `validate_kev` permits a 5% count drop and accepts padded substitutions. The run is marked complete and KEV `ok`. Residual gaps: a replay of the previous list with a newer date is not stopped by any local control, and the first run has no baseline. Closing these requires content authenticity (signature or pinned hash).

**Low**
- **Run-integrity and status:** planted run file reports a healthy latest run (vuln-0001, 3.3, accepted risk per the project plan); unbounded in-memory run loading (vuln-0002, 3.3); oversized run record silently skipped by status (vuln-0013, 3.1).
- **Matcher logic:** same-version boundary misordering hides a reintroduced affected version (vuln-0005, 3.7); OSV no-answer components recorded as known not exploited (vuln-0006, 3.7).
- **Feed and cache handling:** future-dated KEV response freezes genuine updates (vuln-0008, 3.7); total download deadline not enforced during blocking reads (vuln-0009, 3.7); trailing-dot OSV id aborts the run (vuln-0011, 3.7); concurrent run records overwrite each other (vuln-0012, 2.5).

**Controls confirmed**
- SBOM parser limits (depth, file size, duplicate keys, NaN and Infinity, component count) hold under roughly 30,000 fuzzed component cases and 3,000 file mutations.
- Terminal-escape injection is blocked by ASCII allow-lists in the SBOM reader, field discarding in OSV summarization, and `printable()` on status output.
- Path containment holds for OSV id traversal, pre-existing cache symlinks, and evidence `cve_id` values (`CVE_PATTERN` plus `safe_join`).
- Redirects are refused, the host and scheme allow-list holds, and TLS verification is on by default.
- Cache keys are hashed, and purl cache poisoning was not reproduced.

**Open items (not filed)**
- Batch answers are mapped to components by position, with only a count check (feed reorder risk, needs on-path position).
- ECOSYSTEM `limit` events are silently ignored, so an upper bound may be widened (OSV semantics unverified offline).
- PEP 440 local-label stripping in version parsing (over-report direction).
- KEV attribution through upstream CVE links, and the no-purl component urgency policy.
- Batch result positional mapping and a no-purl component policy both need maintainer decisions.

**Systemic themes:** the tool asserts completeness and correctness from structural validity or from the absence of an answer, and it does not fail closed on ambiguous component identity, feed integrity, or run records.

# Recommendations

**Immediate**
1. Fix the completeness gap for KEV and OSV. Reject any KEV list that drops a previously seen CVE id, and mark it stale so the run is incomplete (vuln-0007). Add an integrity check on the KEV file, such as a signature or pinned hash, to close the replay variant.
2. Fail closed on Maven identity. Treat slash-separated namespaces and upper-case coordinates as UNKNOWN with an incomplete result (vuln-0004). Update the existing test that expects the slash form to be accepted.

**Short-term**
3. Correct the matcher's handling of an absent OSV answer and of same-version range boundaries (vuln-0005, vuln-0006). The patches verified in the working copy are small (one sort line and three flags). Add regression tests for both cases.
4. Make `status` treat an oversized, unreadable, or tampered latest run as incomplete rather than skipping or trusting it (vuln-0001, vuln-0013). Set a total byte budget for run loading (vuln-0002).
5. Harden the feed client: enforce the total download deadline with a non-blocking read, reject future-dated KEV releases beyond a one-day bound, tighten the OSV id pattern to match the cache filename check, and use exclusive-create for run record writes (vuln-0008, vuln-0009, vuln-0011, vuln-0012).

**Medium-term**
6. Resolve the open maintainer decisions: CISA's KEV removal policy, the integrity model for the runs folder, the urgency for components without a purl, and the OSV semantics of `limit` events.
7. Confirm the pinned dependency versions against GHSA, OSV, and NVD with web access. Trivy's offline database reported no vulnerabilities.

**Retest and validation:** after applying the fixes, re-run the test suite. Expected baseline is 411 passed with 2 skipped live tests, plus the new regression tests. Re-run the reproducers for vuln-0004 (slash and upper-case Maven purls must exit incomplete), vuln-0007 (KEV omission must be rejected with the saved copy kept), and vuln-0005 and vuln-0006 (regression tests must fail on the old code and pass on the new).

