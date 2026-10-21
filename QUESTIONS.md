# Open Questions for Fares

Questions that came up while building on autopilot. Each one has a **temporary** safe choice that was used so work could continue. Please answer or change them.

| # | Question | Temporary choice used | Status |
|---|---|---|---|
| 1 | Should an SBOM with no `components` at all be rejected, or accepted with a warning? | Accepted, but the reader returns a loud warning ("SBOM has no components") so it can never look like "all clear". | temporary |
| 2 | Pin the two GitHub Actions in `.github/workflows/gitleaks.yml` (`checkout@v4`, `gitleaks-action@v2`) to full commit codes? | Left on version tags for now: I may only use the network for OSV/KEV, so I could not look up the real commit codes, and I will not invent them. | needs Fares (before the first push) |
| 3 | Which exit code should `cra check-sbom` give when some components are UNKNOWN? | 1 ("a human must look"); 0 = all fine, 2 = file rejected. | temporary |
| 4 | When all sources are fine but some components are UNKNOWN (e.g. the firmware without a purl), what should the final message say? | It says "no exploited vulnerabilities found among the checked components" AND lists the UNKNOWN components loudly as "could NOT be checked". It never says plain "all clear". | temporary |
