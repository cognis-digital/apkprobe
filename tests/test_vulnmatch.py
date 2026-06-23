"""Tests for vuln correlation against the bundled OSV DB (apkprobe.vulnmatch).

These prove *real* lookups against the bundled corpus (CVE-2021-44228 / log4j,
lodash, jackson-databind) plus the CVSS scoring used to band severities. No
network, no fabricated data.
"""

from __future__ import annotations

import pytest

from apkprobe.components import ComponentEvidence
from apkprobe.vulndb_local import VulnDB
from apkprobe.vulnmatch import (
    VulnHit, VulnReport, correlate, enrich_apk, render_text,
    cvss3_base_score, cvss_label,
)


@pytest.fixture(scope="module")
def db() -> VulnDB:
    d = VulnDB()
    d.count()   # warm the cache once for the module
    return d


# --- CVSS scoring (exact, against published reference scores) ---------------- #
def test_cvss_log4shell_is_10():
    score = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert score == 10.0


def test_cvss_jackson_xxe_is_7_5():
    score = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N")
    assert score == 7.5


def test_cvss_lodash_redos_is_5_3():
    score = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L")
    assert score == 5.3


def test_cvss_no_impact_is_zero():
    score = cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert score == 0.0


def test_cvss_unparseable_returns_none():
    assert cvss3_base_score("not a vector") is None


def test_cvss_v30_supported():
    # v3.0 vectors share the same base formula
    score = cvss3_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert score is not None and score >= 7.0


def test_label_critical():
    assert cvss_label("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == "CRITICAL"


def test_label_high():
    assert cvss_label("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N") == "HIGH"


def test_label_medium():
    assert cvss_label("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L") == "MEDIUM"


def test_label_empty_for_blank():
    assert cvss_label("") == ""


def test_label_passthrough_for_words():
    assert cvss_label("HIGH") == "HIGH"
    assert cvss_label("critical") == "CRITICAL"
    assert cvss_label("Moderate") == "MEDIUM"


def test_label_cvss4_high():
    v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert cvss_label(v) == "HIGH"


def test_label_cvss4_low_when_no_impact():
    v = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
    assert cvss_label(v) == "LOW"


# --- real DB lookups (the heart of the requirement) -------------------------- #
def test_log4j_cve_resolves(db):
    hits = db.by_cve("CVE-2021-44228")
    assert hits
    assert any("log4j" in p.lower() for r in hits for p in r.get("packages", []))


def test_correlate_advisory_id(db):
    ev = [ComponentEvidence("cve", "CVE-2021-44228", where="lic.txt")]
    hits = correlate(ev, db)
    assert hits
    assert hits[0].confidence == "exact-advisory"
    assert hits[0].cve == "CVE-2021-44228"


def test_correlate_ghsa_id_maps_to_cve(db):
    ev = [ComponentEvidence("ghsa", "GHSA-JFH8-C2JP-5V3Q", where="lic.txt")]
    hits = correlate(ev, db)
    assert hits
    assert hits[0].cve == "CVE-2021-44228"


def test_correlate_maven_coordinate(db):
    ev = [ComponentEvidence("maven", "org.apache.logging.log4j:log4j-core",
                            "2.14.1", "lic.txt", "Maven")]
    hits = correlate(ev, db)
    assert hits
    assert any("log4j" in h.matched_package.lower() for h in hits)


def test_correlate_npm_lodash(db):
    ev = [ComponentEvidence("npm", "lodash", "4.17.4", "package.json", "npm")]
    hits = correlate(ev, db)
    assert hits
    assert all(h.component_kind == "npm" for h in hits)


def test_correlate_jackson_databind(db):
    ev = [ComponentEvidence("maven", "com.fasterxml.jackson.core:jackson-databind",
                            "2.9.8", "lic.txt", "Maven")]
    hits = correlate(ev, db)
    assert hits  # jackson-databind has many advisories in OSV


def test_correlate_unknown_package_no_hits(db):
    ev = [ComponentEvidence("npm", "this-package-does-not-exist-xyz-123", "1.0",
                            "package.json", "npm")]
    hits = correlate(ev, db)
    assert hits == []


def test_correlate_empty_evidence(db):
    assert correlate([], db) == []


def test_correlate_caps_per_component(db):
    ev = [ComponentEvidence("npm", "lodash", "4.17.4", "package.json", "npm")]
    hits = correlate(ev, db, max_hits_per_component=2)
    assert len(hits) <= 2


def test_correlate_dedups_same_advisory(db):
    # same coordinate twice -> no duplicate (component,where,id) rows
    ev = [ComponentEvidence("npm", "lodash", "4.17.4", "package.json", "npm")]
    hits = correlate(ev, db)
    keys = [(h.component, h.where, h.vuln_id) for h in hits]
    assert len(keys) == len(set(keys))


def test_correlate_ranking_exact_first(db):
    ev = [
        ComponentEvidence("npm", "lodash", "4.17.4", "package.json", "npm"),
        ComponentEvidence("cve", "CVE-2021-44228", where="lic.txt"),
    ]
    hits = correlate(ev, db)
    assert hits[0].confidence == "exact-advisory"


# --- VulnHit / VulnReport -------------------------------------------------- #
def test_vulnhit_cve_property():
    h = VulnHit("lodash", "npm", "p.json", "GHSA-x", ["CVE-2020-0001"], "npm",
                "", "summary", "coordinate", "lodash")
    assert h.cve == "CVE-2020-0001"


def test_vulnhit_cve_falls_back_to_id():
    h = VulnHit("lodash", "npm", "p.json", "GHSA-x", [], "npm",
                "", "summary", "coordinate", "lodash")
    assert h.cve == "GHSA-x"


def test_vulnhit_severity_label():
    h = VulnHit("x", "npm", "p", "GHSA", [], "npm",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "s", "coordinate", "x")
    assert h.severity_label == "CRITICAL"


def test_vulnhit_to_dict_has_derived_fields():
    h = VulnHit("x", "npm", "p", "GHSA", ["CVE-2020-1"], "npm",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", "s", "coordinate", "x")
    d = h.to_dict()
    assert d["cve"] == "CVE-2020-1"
    assert d["severity_label"] == "HIGH"


def test_report_to_dict_shape():
    r = VulnReport(package="com.x", db_count=100)
    d = r.to_dict()
    for key in ("package", "db_count", "evidence_count", "hit_count",
                "distinct_advisories", "cve_ids", "evidence", "hits"):
        assert key in d


def test_report_cve_ids_dedup():
    h1 = VulnHit("a", "npm", "p", "GHSA-1", ["CVE-2020-1"], "npm", "", "s", "coordinate", "a")
    h2 = VulnHit("a", "npm", "p", "GHSA-2", ["CVE-2020-1"], "npm", "", "s", "coordinate", "a")
    r = VulnReport(hits=[h1, h2])
    assert r.cve_ids == ["CVE-2020-1"]


# --- end-to-end enrichment over a real APK fixture ------------------------- #
def test_enrich_apk_finds_log4shell(vuln_apk_path, db):
    r = enrich_apk(vuln_apk_path, db=db)
    assert "CVE-2021-44228" in r.cve_ids
    assert r.max_severity_label() == "CRITICAL"


def test_enrich_apk_tags_package(vuln_apk_path, db):
    r = enrich_apk(vuln_apk_path, db=db)
    assert r.package == "com.acme.app"


def test_enrich_apk_db_count(vuln_apk_path, db):
    r = enrich_apk(vuln_apk_path, db=db)
    assert r.db_count >= 100000


def test_enrich_apk_has_evidence(vuln_apk_path, db):
    r = enrich_apk(vuln_apk_path, db=db)
    assert len(r.evidence) >= 5


def test_enrich_clean_apk_no_advisory_hits(clean_apk_path, db):
    r = enrich_apk(clean_apk_path, db=db)
    assert "CVE-2021-44228" not in r.cve_ids


def test_render_text_contains_package_and_count(vuln_apk_path, db):
    r = enrich_apk(vuln_apk_path, db=db)
    out = render_text(r)
    assert "com.acme.app" in out
    assert "CVE-2021-44228" in out
    assert "records" in out


def test_render_text_no_hits_message(clean_apk_path, db):
    r = enrich_apk(clean_apk_path, db=db)
    r.hits = []
    out = render_text(r)
    assert "no components matched" in out
