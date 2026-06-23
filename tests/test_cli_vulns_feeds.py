"""CLI tests for the `vulns` and `feeds` subcommands (offline only)."""

from __future__ import annotations

import json

import pytest

from apkprobe.cli import main


def test_vulns_table_exit_high(vuln_apk_path, capsys):
    # log4shell is CRITICAL -> exit 1 (CI gate)
    code = main(["vulns", vuln_apk_path])
    out = capsys.readouterr().out
    assert "CVE-2021-44228" in out
    assert code == 1


def test_vulns_json_output(vuln_apk_path, capsys):
    code = main(["vulns", vuln_apk_path, "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["package"] == "com.acme.app"
    assert data["hit_count"] >= 1
    assert "CVE-2021-44228" in data["cve_ids"]
    assert code == 1


def test_vulns_format_json_alias(vuln_apk_path, capsys):
    main(["vulns", vuln_apk_path, "--format", "json"])
    out = capsys.readouterr().out
    json.loads(out)  # must be valid JSON


def test_vulns_cve_only_filter(vuln_apk_path, capsys):
    main(["vulns", vuln_apk_path, "--json", "--cve-only"])
    data = json.loads(capsys.readouterr().out)
    for h in data["hits"]:
        assert h["cve"].startswith("CVE-")


def test_vulns_min_confidence_filter(vuln_apk_path, capsys):
    main(["vulns", vuln_apk_path, "--json", "--min-confidence", "exact-advisory"])
    data = json.loads(capsys.readouterr().out)
    for h in data["hits"]:
        assert h["confidence"] == "exact-advisory"


def test_vulns_clean_apk_exit_zero(clean_apk_path, capsys):
    code = main(["vulns", clean_apk_path])
    capsys.readouterr()
    assert code == 0


def test_vulns_missing_file(capsys):
    code = main(["vulns", "/no/such/file.apk"])
    err = capsys.readouterr().err
    assert code == 1
    assert "error" in err.lower()


def test_vulns_alternate_db_flag(vuln_apk_path, tmp_path, capsys):
    # point --db at an empty gz; should load 0 records and find nothing
    import gzip
    empty = tmp_path / "empty.jsonl.gz"
    with gzip.open(empty, "wt", encoding="utf-8") as fh:
        fh.write("")
    code = main(["vulns", vuln_apk_path, "--json", "--db", str(empty)])
    data = json.loads(capsys.readouterr().out)
    assert data["db_count"] == 0
    assert data["hit_count"] == 0
    assert code == 0


# --- feeds passthrough ------------------------------------------------------- #
def test_feeds_list(capsys):
    code = main(["feeds", "list"])
    out = capsys.readouterr().out
    assert "cisa-kev" in out
    assert "osv" in out
    assert code == 0


def test_feeds_list_domain(capsys):
    code = main(["feeds", "list", "--domain", "vuln"])
    out = capsys.readouterr().out
    assert "nvd-cve" in out
    assert code == 0


def test_feeds_get_offline_uncached_errors(capsys):
    # an uncached feed in offline mode must error, never hit the network
    import os, tempfile
    os.environ["COGNIS_FEEDS_CACHE"] = tempfile.mkdtemp()
    code = main(["feeds", "get", "epss", "--offline"])
    err = capsys.readouterr().err
    assert code == 1
    assert "epss" in err
