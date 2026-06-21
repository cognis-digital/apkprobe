import pytest

from apkprobe.analyzer import analyze_apk
from apkprobe.rules import Severity


def test_full_apk_scan(apk_path):
    report = analyze_apk(apk_path)
    assert report.package == "com.acme.app"
    assert "v1 (JAR)" in report.signature_schemes
    titles = [f.title for f in report.findings]
    assert "Application is debuggable" in titles
    assert any("embedded secret" in t.lower() for t in titles)


def test_unsigned_apk_flagged(tmp_path, manifest_axml):
    from tests.conftest import build_apk
    p = tmp_path / "unsigned.apk"
    p.write_bytes(build_apk(manifest_axml, signed=False))
    report = analyze_apk(str(p))
    assert any("unsigned" in f.title.lower() for f in report.findings)


def test_max_severity(apk_path):
    report = analyze_apk(apk_path)
    assert report.max_severity() >= int(Severity.HIGH)


# --- scopeward gating -------------------------------------------------------

scopeward = pytest.importorskip("scopeward")


def _authorizer(packages, key="k"):
    from datetime import datetime, timedelta, timezone
    from scopeward.scope import Scope, Target
    from scopeward.signing import sign_scope
    from scopeward.authz import Authorizer
    now = datetime.now(timezone.utc)
    scope = Scope(
        engagement_id="E", client="C", authorized_by="A", roe="R",
        not_before=now - timedelta(days=1), not_after=now + timedelta(days=1),
        targets=[Target("android", p) for p in packages],
        allowed_modules=["apkprobe"],
    )
    sign_scope(scope, key)
    return Authorizer(scope, key)


def test_gating_allows_authorized_package(apk_path):
    report = analyze_apk(apk_path, authorizer=_authorizer(["com.acme.app"]))
    assert report.package == "com.acme.app"


def test_gating_refuses_unauthorized_package(apk_path):
    from scopeward.authz import ScopeViolation
    with pytest.raises(ScopeViolation):
        analyze_apk(apk_path, authorizer=_authorizer(["com.someoneelse.app"]))
