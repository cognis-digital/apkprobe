"""Tests for the offline component-evidence harvester (apkprobe.components)."""

from __future__ import annotations

from apkprobe.components import (
    ComponentEvidence, extract_components, extract_from_text, split_evidence,
)


# --- text harvesting --------------------------------------------------------- #
def test_extract_cve_id():
    ev = extract_from_text("notes.txt", "fixed CVE-2021-44228 in this build")
    cves = [e for e in ev if e.kind == "cve"]
    assert len(cves) == 1
    assert cves[0].name == "CVE-2021-44228"
    assert cves[0].where == "notes.txt"


def test_extract_cve_is_uppercased():
    ev = extract_from_text("n.txt", "cve-2019-10744 lodash")
    assert any(e.name == "CVE-2019-10744" for e in ev if e.kind == "cve")


def test_extract_ghsa_id():
    ev = extract_from_text("notes.txt", "GHSA-jfh8-c2jp-5v3q advisory")
    ghsa = [e for e in ev if e.kind == "ghsa"]
    assert ghsa and ghsa[0].name == "GHSA-JFH8-C2JP-5V3Q"


def test_extract_maven_coordinate_with_version():
    ev = extract_from_text("deps.txt", "org.apache.logging.log4j:log4j-core:2.14.1")
    maven = [e for e in ev if e.kind == "maven"]
    assert maven
    assert maven[0].name == "org.apache.logging.log4j:log4j-core"
    assert maven[0].version == "2.14.1"
    assert maven[0].ecosystem == "Maven"


def test_extract_maven_coordinate_without_version():
    ev = extract_from_text("deps.txt", "com.fasterxml.jackson.core:jackson-databind")
    maven = [e for e in ev if e.kind == "maven"]
    assert maven and maven[0].version == ""


def test_maven_skips_android_namespace():
    ev = extract_from_text("m.xml", 'android:name="com.acme.Foo" android:exported="true"')
    assert not [e for e in ev if e.kind == "maven" and e.name.startswith("android")]


def test_maven_skips_urls():
    ev = extract_from_text("c.txt", "https://example.com:8080 http://a.b:9090")
    assert not [e for e in ev if e.kind == "maven" and e.name.startswith(("http", "www"))]


def test_no_evidence_in_plain_text():
    ev = extract_from_text("readme.txt", "just some prose with no coordinates")
    assert ev == []


def test_extract_multiple_cves_dedup():
    ev = extract_from_text("x.txt", "CVE-2021-44228 and again CVE-2021-44228")
    cves = [e for e in ev if e.kind == "cve"]
    assert len(cves) == 1  # deduped


# --- package.json harvesting ------------------------------------------------- #
def test_package_json_name_and_deps():
    blob = '{"name":"myapp","version":"2.0.0","dependencies":{"lodash":"4.17.4","axios":"0.18.0"}}'
    ev = extract_from_text("assets/www/package.json", blob)
    names = {e.name for e in ev if e.kind == "npm"}
    assert "myapp" in names
    assert "lodash" in names
    assert "axios" in names


def test_package_json_devdeps():
    blob = '{"name":"a","devDependencies":{"jest":"26.0.0"}}'
    ev = extract_from_text("package.json", blob)
    assert any(e.name == "jest" for e in ev if e.kind == "npm")


def test_package_json_lowercased():
    blob = '{"name":"MyApp","dependencies":{"LoDash":"1.0.0"}}'
    ev = extract_from_text("package.json", blob)
    names = {e.name for e in ev if e.kind == "npm"}
    assert "myapp" in names and "lodash" in names


def test_package_json_invalid_is_ignored():
    ev = extract_from_text("package.json", "not json {{{")
    assert not [e for e in ev if e.kind == "npm"]


def test_non_packagejson_json_not_parsed_as_npm():
    # arbitrary json file should not be treated as a package manifest
    ev = extract_from_text("config.json", '{"name":"x","dependencies":{"y":"1"}}')
    assert not [e for e in ev if e.kind == "npm"]


# --- zip-level extraction ---------------------------------------------------- #
def test_extract_from_apk_finds_all_kinds(vuln_apk_path):
    ev = extract_components(vuln_apk_path)
    kinds = {e.kind for e in ev}
    assert "cve" in kinds
    assert "ghsa" in kinds
    assert "maven" in kinds
    assert "npm" in kinds
    assert "native" in kinds


def test_native_lib_name_extracted(vuln_apk_path):
    ev = extract_components(vuln_apk_path)
    natives = {e.name for e in ev if e.kind == "native"}
    assert "sqlite" in natives


def test_native_skip_list(vuln_apk_path):
    ev = extract_components(vuln_apk_path)
    natives = {e.name for e in ev if e.kind == "native"}
    assert "c++_shared" not in natives


def test_versioned_js_lib_extracted(vuln_apk_path):
    ev = extract_components(vuln_apk_path)
    js = [e for e in ev if e.kind == "npm" and e.where.endswith(".js")]
    assert any(e.name == "lodash" for e in js)


def test_versioned_js_version_no_min_suffix(vuln_apk_path):
    ev = extract_components(vuln_apk_path)
    js = [e for e in ev if e.kind == "npm" and e.where.endswith(".min.js")]
    assert js
    assert all(".min" not in e.version for e in js)
    assert any(e.version == "4.17.4" for e in js)


def test_clean_apk_has_no_evidence(clean_apk_path):
    ev = extract_components(clean_apk_path)
    # the embedded strings.xml has no coords/advisories
    assert all(e.kind not in ("cve", "ghsa") for e in ev)


def test_evidence_is_deduped(vuln_apk_path):
    ev = extract_components(vuln_apk_path)
    keys = [(e.kind, e.name, e.version, e.where) for e in ev]
    assert len(keys) == len(set(keys))


def test_evidence_carries_provenance(vuln_apk_path):
    ev = extract_components(vuln_apk_path)
    assert all(e.where for e in ev)


# --- split_evidence ---------------------------------------------------------- #
def test_split_evidence_partitions():
    items = [
        ComponentEvidence("cve", "CVE-2021-44228"),
        ComponentEvidence("ghsa", "GHSA-AAAA-BBBB-CCCC"),
        ComponentEvidence("maven", "g:a", "1.0"),
        ComponentEvidence("npm", "lodash", "4.0"),
    ]
    advisories, packages = split_evidence(items)
    assert "CVE-2021-44228" in advisories
    assert "GHSA-AAAA-BBBB-CCCC" in advisories
    assert len(packages) == 2


def test_component_evidence_to_dict_roundtrip():
    e = ComponentEvidence("maven", "g:a", "1.2.3", "x.txt", "Maven")
    d = e.to_dict()
    assert d["kind"] == "maven"
    assert d["name"] == "g:a"
    assert d["version"] == "1.2.3"
    assert d["ecosystem"] == "Maven"


def test_component_evidence_is_frozen():
    import dataclasses
    e = ComponentEvidence("cve", "CVE-2020-0001")
    try:
        e.name = "x"
        assert False, "should be frozen"
    except dataclasses.FrozenInstanceError:
        pass
