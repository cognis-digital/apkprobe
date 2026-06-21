from apkprobe.manifest import AppManifest
from apkprobe.rules import analyze_manifest, Severity
from tests._axml_fixture import encode
from tests.conftest import manifest_tree


def _titles(findings):
    return [f.title for f in findings]


def test_flags_debuggable_and_cleartext():
    m = AppManifest.from_axml(encode(manifest_tree(
        debuggable=("bool", True), usesCleartextTraffic=("bool", True))))
    findings = analyze_manifest(m)
    titles = _titles(findings)
    assert "Application is debuggable" in titles
    assert "Cleartext (HTTP) traffic permitted" in titles


def test_clean_app_has_fewer_findings():
    clean = AppManifest.from_axml(encode(manifest_tree(usesCleartextTraffic=("bool", False))))
    findings = analyze_manifest(clean)
    assert "Application is debuggable" not in _titles(findings)
    assert "Cleartext (HTTP) traffic permitted" not in _titles(findings)


def test_exported_component_flagged():
    m = AppManifest.from_axml(encode(manifest_tree()))
    findings = analyze_manifest(m)
    assert any("Exported service without permission" in t for t in _titles(findings))


def test_sensitive_permission_surfaced():
    m = AppManifest.from_axml(encode(manifest_tree()))
    findings = analyze_manifest(m)
    assert any("READ_SMS" in t for t in _titles(findings))


def test_severity_ordering_for_debuggable():
    m = AppManifest.from_axml(encode(manifest_tree(debuggable=("bool", True))))
    findings = analyze_manifest(m)
    dbg = next(f for f in findings if f.title == "Application is debuggable")
    assert int(Severity.parse(dbg.severity)) == int(Severity.HIGH)


def test_findings_carry_mastg_refs():
    m = AppManifest.from_axml(encode(manifest_tree(debuggable=("bool", True))))
    dbg = next(f for f in analyze_manifest(m) if f.title == "Application is debuggable")
    assert dbg.masvs.startswith("MASVS-")
    assert dbg.mastg_test.startswith("MASTG-")
