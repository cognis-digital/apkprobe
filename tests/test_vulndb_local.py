"""Offline tests: bundled vuln DB ships 100k+ real vulns with detailed metadata."""

import pytest

from apkprobe.vulndb_local import VulnDB, count


@pytest.fixture(scope="module")
def db():
    d = VulnDB()
    d.count()
    return d


def test_has_100k_plus_vulns(db):
    assert db.count() >= 100000


def test_module_count_helper():
    assert count() >= 100000


def test_detailed_metadata(db):
    r = next(iter(db))
    for f in ("id", "aliases", "ecosystem", "summary", "severity", "packages"):
        assert f in r


def test_cve_lookup_returns_list(db):
    assert isinstance(db.by_cve("CVE-2021-44228"), list)


def test_log4shell_resolves(db):
    hits = db.by_cve("CVE-2021-44228")
    assert hits
    assert any("log4j" in p.lower() for r in hits for p in r["packages"])


def test_cve_lookup_case_insensitive(db):
    assert db.by_cve("cve-2021-44228") == db.by_cve("CVE-2021-44228")


def test_unknown_cve_empty(db):
    assert db.by_cve("CVE-0000-00000") == []


def test_package_lookup(db):
    assert db.by_package("lodash") or db.by_package("django")


def test_package_lookup_case_insensitive(db):
    assert db.by_package("LODASH") == db.by_package("lodash")


def test_package_lookup_ecosystem_filter(db):
    npm = db.by_package("lodash", ecosystem="npm")
    assert npm
    assert all(r["ecosystem"].lower() == "npm" for r in npm)


def test_search_substring(db):
    hits = db.search("deserialization", limit=5)
    assert hits
    assert all("deserialization" in r["summary"].lower() for r in hits)


def test_search_limit_respected(db):
    assert len(db.search("the", limit=3)) <= 3


def test_iter_yields_dicts(db):
    it = iter(db)
    assert isinstance(next(it), dict)


def test_alternate_empty_db(tmp_path):
    import gzip
    p = tmp_path / "empty.jsonl.gz"
    with gzip.open(p, "wt", encoding="utf-8") as fh:
        fh.write("")
    d = VulnDB(str(p))
    assert d.count() == 0
    assert d.by_cve("CVE-2021-44228") == []


def test_missing_db_file_is_empty(tmp_path):
    d = VulnDB(str(tmp_path / "nope.jsonl.gz"))
    assert d.count() == 0
