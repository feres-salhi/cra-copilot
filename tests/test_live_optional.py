"""OPTIONAL live test: talks to the REAL internet (OSV.dev and CISA KEV).

It is skipped unless you switch it on on purpose:
    PowerShell:  $env:CRA_LIVE_TEST = "1"; .venv\\Scripts\\python -m pytest tests/test_live_optional.py -v
It only reads public data. It writes only into a temporary folder.
"""

import os

import pytest

from src import news_watcher as nw

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("CRA_LIVE_TEST") != "1", reason="live test: set CRA_LIVE_TEST=1 to run"),
]

LOG4J_2141 = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def test_real_kev_download_is_valid_and_contains_log4shell(tmp_path):
    data, status = nw.fetch_kev(tmp_path)
    assert status["status"] == "ok", status
    assert "CVE-2021-44228" in nw.kev_cve_ids(data)


def test_real_osv_knows_log4shell_for_log4j_2_14_1(tmp_path):
    purl_vulns, vulns, status = nw.fetch_osv([LOG4J_2141], tmp_path)
    assert status["status"] == "ok", status
    assert "GHSA-jfh8-c2jp-5v3q" in purl_vulns[LOG4J_2141]
    assert vulns["GHSA-jfh8-c2jp-5v3q"]["aliases"] == ["CVE-2021-44228"]
