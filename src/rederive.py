"""Phase 4: re-derive "affected" from the SBOM instead of trusting a run record (PLAN.md section (i), item 3).

A run record is sealed only with an unkeyed fingerprint (decision S7): anyone who knows the code can write one that says
"this component is affected". So `cra draft` and `cra approve` run the matcher again on the real SBOM file and the saved
data on this computer (no download), and the case is only used if the same finding comes out.
Only normal, testable code decides this (CLAUDE.md trust rule 1).
"""

import hashlib

from src import matcher, news_watcher, report_facts
from src.sbom_reader import SbomError, load_sbom_bytes, read_product_config, read_sbom_bytes

SAME_FINDING_KEYS = ("purl", "component", "version", "exploited_cve", "exploited_via", "exploited_cve_matched_on")


class RederiveError(Exception):
    """The case cannot be confirmed from the SBOM and the saved data. The message is safe to show."""


def load_inputs(sbom_path, config_path, expected_sbom_sha256, expected_product):
    """(config, components, sbom_sha256). SbomError / ConfigError (input rejected) pass through.

    The SBOM must be byte for byte the file the run (or the earlier draft) used, and the config must give the same product.
    """
    raw = read_sbom_bytes(sbom_path)  # read ONCE: the fingerprint and the parsed components come from the same bytes
    before = hashlib.sha256(raw).hexdigest()
    sbom = load_sbom_bytes(raw)
    config = read_product_config(config_path)
    if not expected_sbom_sha256 or before != expected_sbom_sha256:
        raise RederiveError("this is not the SBOM this run used (its fingerprint is different): use the same file as for `cra run`")
    if config != expected_product:
        raise RederiveError("this is not the product the run used (the config gives other values): use the same config as for `cra run`")
    return config, sbom.components, before


def rederive(components, config, expected, cache_dir, evidence_dir, now):
    """Run the matcher again on the SBOM components and the saved data; return (finding, facts without awareness, feeds).

    `feeds` is the saved data that was used: take the KEV list from it, not from a second read of the cache.

    `expected` is the finding that is claimed (from a run record, or rebuilt from facts.json at approval).
    """
    feeds = news_watcher.feeds_from_cache(components, cache_dir, now)
    result = matcher.evaluate(components, feeds, evidence_dir)
    for finding in result["findings"]:
        if (finding["action"] == "REPORT_CASE" and finding["status"] == matcher.AFFECTED
                and all(finding.get(key) == expected.get(key) for key in SAME_FINDING_KEYS)):
            try:
                facts = report_facts.build_facts(config, finding, kev_ids=feeds.kev_ids, evidence_dir=evidence_dir)
            except report_facts.FactsError as error:
                raise RederiveError(f"the facts cannot be built: {error}") from error
            return finding, facts, feeds
    raise RederiveError("the case could not be re-derived from the SBOM and the saved data: the same possible report case "
                        "does not come out (the SBOM, the saved vulnerability data or the saved KEV list say something else)")
