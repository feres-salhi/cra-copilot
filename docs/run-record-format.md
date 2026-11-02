# Run record format (`runs/*.json`)

Every time `cra run` finishes, it saves one file in `runs/`, for example `runs/2026-11-02T01-03-20Z.json`.
The file name is the UTC time the run finished (`YYYY-MM-DDTHH-MM-SSZ`). If two runs finish in the same second, the
second one gets `-0002` before `.json`, and so on.

This page explains every field in plain words, so that a dashboard (for example Power BI in Phase 5) can read the files
later. The facts below were checked against the code (`src/cli.py`, `src/matcher.py`, `src/news_watcher.py`) and against
the real files in `runs/`.

## The basics

- Each file is **one JSON object** (one run). To see the history, read all files in the folder and sort by `finished_at`.
- **Times** are text in ISO 8601 form, in UTC, for example `2026-11-02T01:03:20.303447+00:00`.
- **`true` / `false`** are real JSON booleans. **`null`** means "nothing".
- **Never edit these files by hand.** Each file has a `seal` (see below); a changed file is no longer trusted by the tool
  and shows up in `cra status` as damaged.
- **Old files stay readable.** The format is backward compatible: fields were only ever added, never renamed or removed.
  The tool treats a missing field as "not known", never as "ok". A dashboard should do the same (see "Old and odd files").

## Fields of a normal run (written by `cra run`)

| Field | Type | Meaning |
|---|---|---|
| `started_at` | text (time) | When the run started. |
| `finished_at` | text (time) | When the run finished. This is the time `cra status` uses. Use it as the time axis of a dashboard. |
| `complete` | true / false | Whether the RESULT is complete. It is `true` only if both download sources were ok, the SBOM had no warnings and no finding had a data gap. A run with an UNKNOWN component (for example a component without a purl) is therefore **never** complete. Do not read this as "the machine worked": see `sources`. |
| `report_cases` | whole number | How many findings are a POSSIBLE REPORT CASE (the component is affected AND the vulnerability is actively exploited). This counts findings, not CVEs: the same CVE under two advisory ids counts twice. |
| `needs_human` | true / false | `true` if at least one finding needs any human action (its `action` is not `NONE`). |
| `product` | object | The product this run was for, copied from the product config file (see below). |
| `sbom_sha256` | text, or `null` | A fingerprint (SHA-256) of the SBOM file used. `null` if the file could not be read afterwards. The same SBOM always gives the same fingerprint. |
| `folders` | object | Which folders the run used (see below). |
| `sources` | object | The state of each download source. Keys: `kev` and `osv` (see below). |
| `components` | object | `checked` and `unchecked` (see below). |
| `sbom_warnings` | list of text | Warnings about the SBOM (for example "no components"). Empty list = no warnings. |
| `result` | object | What the matcher found (see below). |
| `seal` | text | A fingerprint of the whole record, used to detect changes (see below). |

### `product`

| Field | Meaning |
|---|---|
| `product_name` | Name of the product (fake demo data in this project). |
| `manufacturer` | Name of the manufacturer. |
| `member_states` | List of EU country codes where the product is sold, for example `["DE", "AT", "FR"]`. |

### `folders`

| Field | Meaning |
|---|---|
| `cache` | Folder with the saved downloads. |
| `runs` | Folder with the run records (this folder). |
| `evidence` | Folder where a human can put evidence files. |
| `evidence_folder_exists` | `true` if the evidence folder existed during the run. |

These are full paths on the computer that made the run. A dashboard that is shared with other people should leave them out.

### `sources`

Two entries, `kev` (the CISA list of known exploited vulnerabilities) and `osv` (the public vulnerability database).
Each entry has:

| Field | Meaning |
|---|---|
| `status` | **`ok`** = downloaded and checked now. **`stale`** = the download failed, so an older saved copy was used (or, for OSV, some answers came from an older copy). **`failed`** = no usable data. |
| `detail` | A sentence in plain words about what happened. |
| `downloaded_at` | (`kev` only) When the KEV list was downloaded. |
| `max_count` | (`kev` only) The most entries the list has ever had. The tool uses it to notice a list that lost entries. |
| `sha256` | (`kev` only) A fingerprint of the saved KEV list. |
| `purls_asked` | (`osv` only) How many components (purls) were asked about. |
| `disappeared_ids` | (`kev` only, rare) CVE ids that vanished from the list. Then `status` is `stale` and a human must decide. |

"The machine worked in this run" means **both** `kev.status` and `osv.status` are `ok`. `cra status` uses exactly this for
its 26-hour warning ("is the scheduler still running?"), and **separately** shows whether the latest result was complete.
A dashboard should keep these two ideas apart too: `machine_ok = (kev.status == "ok" and osv.status == "ok")`, and
`complete` as stored.

### `components`

| Field | Meaning |
|---|---|
| `checked` | How many components of the SBOM could be checked (they have a usable purl). |
| `unchecked` | How many could NOT be checked (their status is UNKNOWN; a human must look). |

### `result`

| Field | Meaning |
|---|---|
| `checked` | Number of components the matcher looked at (same number as `components.checked`). |
| `findings` | List with one entry per advisory found (see below). This is the main table for a dashboard. |
| `packages` | Object: for each package (`ecosystem:name`, e.g. `pypi:requests`) one word, `AFFECTED`, `NOT_AFFECTED` or `UNKNOWN`. If any version-finding of the package is AFFECTED, the package counts as AFFECTED. |
| `data_gaps` | How many findings could not be judged because data was missing, cut off or unreadable. Above 0 makes the run incomplete. |
| `ignored_withdrawn` | How many advisories were skipped because their publisher withdrew them. |
| `ignored_withdrawn_ids` | The ids of those withdrawn advisories. |
| `kev_status` | `ok`, `stale` or `failed`: the status of the KEV list during this run, repeated from `sources.kev.status`. |
| `evidence_folder_given` | `true` if an evidence folder was handed to the matcher. |

### One entry of `result.findings`

| Field | Meaning |
|---|---|
| `component` | Name of the software component. |
| `version` | Version of the component. |
| `purl` | The package URL that names the component exactly (e.g. `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`). `null` if the SBOM had none. |
| `ecosystem` | Where the package lives, for example `maven` or `pypi`. |
| `vulnerability_id` | The advisory id (for example `GHSA-...` or `PYSEC-...`). `null` for findings that are not about one advisory (for example an UNKNOWN component). |
| `cve_ids` | List of the CVE ids of this advisory. The same vulnerability often appears as several findings (a GHSA and a PYSEC one) with the **same** `cve_ids`. `cra run` shows them as one line, but the record keeps every finding. To count vulnerabilities, count distinct `cve_ids` (with component and version), not findings. |
| `status` | `AFFECTED`, `NOT_AFFECTED` or `UNKNOWN`. Decided only by normal tested code, never by AI. |
| `rule` | Which rule decided `status`, in short form, for example `osv_exact_version_list` (the version is in the advisory's list) or `component_unknown: no purl`. Other values describe missing data, for example `osv_gave_no_answer`, `osv_details_missing`, `record_malformed`, `record_truncated`, `version_list_too_long`. |
| `exploited` | `true` if the vulnerability is known to be actively exploited (KEV list, or a human evidence file). |
| `exploited_known` | `false` if the tool could NOT check whether it is exploited (no fresh KEV list or no vulnerability list). Then the finding needs urgent human review. |
| `exploited_via` | `kev` or `evidence_file` when `exploited` is true, otherwise `null`. |
| `exploited_cve` | The CVE id that was found exploited, or `null`. |
| `exploited_cve_matched_on` | Where the link to `exploited_cve` came from: `id` (the advisory id itself is the CVE), `alias` (the advisory lists the CVE as an alias; the normal case for GHSA) or `upstream` (only an "upstream" reference; the weakest link, a human should confirm). `null` if not exploited. |
| `evidence` | When a human evidence file was used: an object with `source_url` and `date` (YYYY-MM-DD). Otherwise `null`. |
| `evidence_problem` | List of CVE ids that have an evidence file which could not be used (broken file). Normally an empty list. |
| `action` | What should happen next: **`REPORT_CASE`** = a POSSIBLE REPORT CASE (a human decides if it is reportable under the CRA; affected AND exploited), **`URGENT_HUMAN_REVIEW`**, **`HUMAN_REVIEW`**, **`RECORD`** (affected, not known to be exploited; just recorded) or **`NONE`**. |

## The seal

`seal` is a SHA-256 fingerprint over all other fields. The tool uses it to notice a file that was edited or not written by
`cra run`. It is **not a signature** (anyone who knows the code can compute it), so it only protects against accidents and
careless edits. A dashboard does not need to check it, but should not trust files that were edited by hand.

## Old and odd files (what a dashboard must expect)

- **Old files without `seal`.** The very first run record (`2026-10-21T12-26-39Z.json`) was written before the seal existed.
  The tool treats such a file as "not verified". A dashboard can still show it but should mark it.
- **A failed run.** If a run crashes, the tool still saves a short record so that `cra status` does not keep showing an older good
  run. It has `started_at`, `finished_at`, `complete: false`, `error` (the name of the error, e.g. `OSError`), and **empty**
  `sources` and `components` (`{}`), and no `result`, `product`, `report_cases` or `needs_human`. Treat missing fields as "unknown".
  A record with empty `sources` never counts as "the machine worked".
- **Missing fields.** Never assume a field exists. Missing means "not known", not "zero" and not "ok".
- **Future dates.** A run dated in the future means the computer clock was wrong. `cra status` does not use such a run as the
  last good run, and a dashboard should flag it.
- **Damaged files.** A file that is not valid JSON, too large, or has a wrong seal is treated by `cra status` as an
  incomplete run. A dashboard should skip or flag such files, not crash.

## Ideas for a first dashboard (Phase 5)

All can be made from the fields above, without any new data:
- **Machine health over time:** `finished_at` against `kev.status` and `osv.status` (green only if both are `ok`).
- **Result quality over time:** `complete`, `components.unchecked`, `result.data_gaps`.
- **Open work:** `report_cases` and `needs_human` per run; findings with `action` of `REPORT_CASE`, `URGENT_HUMAN_REVIEW`, `HUMAN_REVIEW`.
- **Findings table:** one row per finding in `result.findings`, with the run's `finished_at`; for counting vulnerabilities group by
  `component`, `version` and `cve_ids`.

Nothing in these files is a legal decision. A human decides what is reportable under the CRA, and the tool never sends anything.
