"""Tests for the APK version-diff / regression-detection engine."""

from __future__ import annotations

from apkprobe.manifest import AppManifest, Component
from apkprobe.diff import (
    diff_manifests, diff_reports, render_text, DiffResult, Delta,
    REGRESSION, IMPROVEMENT, NEUTRAL,
)


def mk(**kw) -> AppManifest:
    m = AppManifest(package=kw.pop("package", "com.test.app"),
                    allow_backup=kw.pop("allow_backup", False))
    for k, v in kw.items():
        setattr(m, k, v)
    return m


def comp(kind, name, exported=True, perm=False, filters=0):
    return Component(kind=kind, name=name, exported=exported,
                     has_permission=perm, intent_filters=filters)


class FakeReport:
    def __init__(self, package="com.test.app", schemes=None, findings=None,
                 manifest=None):
        self.package = package
        self.signature_schemes = schemes or []
        self.findings = findings or []
        self.manifest = manifest


class FakeFinding:
    def __init__(self, title, evidence):
        self.title = title
        self.evidence = evidence


# --- no change ------------------------------------------------------------

def test_identical_manifests_unchanged():
    m = mk(permissions=["android.permission.INTERNET"])
    res = diff_manifests(m, mk(permissions=["android.permission.INTERNET"]))
    assert res.verdict == "UNCHANGED"
    assert res.deltas == []
    assert res.risk_delta() == 0


# --- permission deltas ----------------------------------------------------

def test_added_permission_is_regression():
    old = mk(permissions=[])
    new = mk(permissions=["android.permission.READ_SMS"])
    res = diff_manifests(old, new)
    assert res.verdict == "REGRESSED"
    regs = res.regressions()
    assert any(d.kind == "permission.added" for d in regs)
    sms = [d for d in regs if "READ_SMS" in d.detail][0]
    assert sms.weight == 9
    assert "Read SMS/MMS" in sms.detail


def test_removed_permission_is_improvement():
    old = mk(permissions=["android.permission.CAMERA"])
    new = mk(permissions=[])
    res = diff_manifests(old, new)
    assert res.verdict == "IMPROVED"
    assert any(d.kind == "permission.removed" for d in res.improvements())


def test_unknown_added_permission_default_weight():
    res = diff_manifests(mk(), mk(permissions=["com.x.CUSTOM"]))
    d = [x for x in res.regressions() if x.kind == "permission.added"][0]
    assert d.weight == 2


def test_permission_swap_has_both():
    old = mk(permissions=["android.permission.CAMERA"])
    new = mk(permissions=["android.permission.READ_SMS"])
    res = diff_manifests(old, new)
    assert len(res.regressions()) >= 1
    assert len(res.improvements()) >= 1
    assert res.verdict == "REGRESSED"  # regression takes precedence


# --- flag deltas ----------------------------------------------------------

def test_debuggable_turned_on_regression():
    res = diff_manifests(mk(debuggable=False), mk(debuggable=True))
    d = [x for x in res.regressions() if x.kind == "flag.debuggable"][0]
    assert d.weight == 12
    assert "ON" in d.detail


def test_debuggable_turned_off_improvement():
    res = diff_manifests(mk(debuggable=True), mk(debuggable=False))
    assert any(d.kind == "flag.debuggable" and d.classification == IMPROVEMENT
               for d in res.deltas)


def test_cleartext_on_regression():
    res = diff_manifests(mk(uses_cleartext_traffic=False),
                         mk(uses_cleartext_traffic=True))
    assert any(d.kind == "flag.uses_cleartext_traffic"
               and d.classification == REGRESSION for d in res.deltas)


def test_cleartext_none_to_true_regression():
    res = diff_manifests(mk(uses_cleartext_traffic=None),
                         mk(uses_cleartext_traffic=True))
    assert any(d.classification == REGRESSION
               and d.kind == "flag.uses_cleartext_traffic" for d in res.deltas)


def test_allow_backup_on_regression():
    res = diff_manifests(mk(allow_backup=False), mk(allow_backup=True))
    assert any(d.kind == "flag.allow_backup"
               and d.classification == REGRESSION for d in res.deltas)


def test_nsc_removed_regression():
    res = diff_manifests(mk(network_security_config="nsc.xml"),
                         mk(network_security_config=""))
    d = [x for x in res.deltas if x.kind == "flag.network_security_config"][0]
    assert d.classification == REGRESSION
    assert d.weight == 5


def test_nsc_added_improvement():
    res = diff_manifests(mk(network_security_config=""),
                         mk(network_security_config="nsc.xml"))
    d = [x for x in res.deltas if x.kind == "flag.network_security_config"][0]
    assert d.classification == IMPROVEMENT


# --- sdk deltas -----------------------------------------------------------

def test_min_sdk_lowered_regression():
    res = diff_manifests(mk(min_sdk=24), mk(min_sdk=19))
    d = [x for x in res.deltas if x.kind == "sdk.min_lowered"][0]
    assert d.classification == REGRESSION


def test_min_sdk_raised_improvement():
    res = diff_manifests(mk(min_sdk=21), mk(min_sdk=28))
    assert any(d.kind == "sdk.min_raised"
               and d.classification == IMPROVEMENT for d in res.deltas)


# --- package identity -----------------------------------------------------

def test_package_change_regression():
    res = diff_manifests(mk(package="com.a"), mk(package="com.b"))
    d = [x for x in res.regressions() if x.kind == "package.changed"][0]
    assert d.weight == 10


# --- exported component deltas --------------------------------------------

def test_new_unguarded_exported_component_regression():
    old = mk(components=[])
    new = mk(components=[comp("activity", ".New")])
    res = diff_manifests(old, new)
    d = [x for x in res.regressions() if x.kind == "component.exported.added"][0]
    assert "UNGUARDED" in d.detail
    assert d.weight == 3


def test_new_exported_provider_higher_weight():
    res = diff_manifests(mk(), mk(components=[comp("provider", ".P")]))
    d = [x for x in res.deltas if x.kind == "component.exported.added"][0]
    assert d.weight == 5


def test_new_guarded_exported_component_neutral():
    res = diff_manifests(mk(), mk(components=[comp("activity", ".G", perm=True)]))
    d = [x for x in res.deltas if x.kind == "component.exported.added"][0]
    assert d.classification == NEUTRAL
    assert d.weight == 0


def test_removed_exported_component_improvement():
    old = mk(components=[comp("activity", ".Old")])
    new = mk(components=[])
    res = diff_manifests(old, new)
    assert any(d.kind == "component.exported.removed"
               and d.classification == IMPROVEMENT for d in res.deltas)


def test_guard_removed_regression():
    old = mk(components=[comp("activity", ".A", perm=True)])
    new = mk(components=[comp("activity", ".A", perm=False)])
    res = diff_manifests(old, new)
    d = [x for x in res.regressions() if x.kind == "component.guard.removed"][0]
    assert d.weight == 5


def test_guard_added_improvement():
    old = mk(components=[comp("activity", ".A", perm=False)])
    new = mk(components=[comp("activity", ".A", perm=True)])
    res = diff_manifests(old, new)
    assert any(d.kind == "component.guard.added"
               and d.classification == IMPROVEMENT for d in res.deltas)


# --- ordering & risk delta ------------------------------------------------

def test_regressions_sorted_first_by_weight():
    old = mk()
    new = mk(debuggable=True, permissions=["android.permission.INTERNET"],
             components=[comp("activity", ".A")])
    res = diff_manifests(old, new)
    regs = res.regressions()
    weights = [d.weight for d in regs]
    assert weights == sorted(weights, reverse=True)


def test_risk_delta_positive_on_regression():
    res = diff_manifests(mk(), mk(debuggable=True))
    assert res.risk_delta() > 0


def test_risk_delta_negative_on_improvement():
    res = diff_manifests(mk(debuggable=True), mk())
    assert res.risk_delta() < 0


# --- diff_reports (full report level) -------------------------------------

def test_diff_reports_uses_manifests():
    old = FakeReport(manifest=mk())
    new = FakeReport(manifest=mk(debuggable=True))
    res = diff_reports(old, new)
    assert res.verdict == "REGRESSED"


def test_diff_reports_signing_removed():
    old = FakeReport(schemes=["v1 (JAR)"], manifest=mk())
    new = FakeReport(schemes=[], manifest=mk())
    res = diff_reports(old, new)
    d = [x for x in res.regressions() if x.kind == "signing.removed"][0]
    assert d.weight == 8


def test_diff_reports_signing_downgrade():
    old = FakeReport(schemes=["v1 (JAR)", "v2+/v3 (APK Signing Block)"],
                     manifest=mk())
    new = FakeReport(schemes=["v1 (JAR)"], manifest=mk())
    res = diff_reports(old, new)
    d = [x for x in res.deltas if x.kind == "signing.changed"][0]
    assert d.classification == REGRESSION


def test_diff_reports_new_secret_regression():
    old = FakeReport(manifest=mk(), findings=[])
    new = FakeReport(manifest=mk(), findings=[
        FakeFinding("Possible embedded secret: Google API Key",
                    "res/x.json: AIza...abcd")])
    res = diff_reports(old, new)
    d = [x for x in res.regressions() if x.kind == "secret.added"][0]
    assert d.weight == 9


def test_diff_reports_removed_secret_improvement():
    old = FakeReport(manifest=mk(), findings=[
        FakeFinding("Possible embedded secret: Google API Key",
                    "res/x.json: AIza...abcd")])
    new = FakeReport(manifest=mk(), findings=[])
    res = diff_reports(old, new)
    assert any(d.kind == "secret.removed"
               and d.classification == IMPROVEMENT for d in res.deltas)


def test_diff_reports_without_manifests_still_diffs_findings():
    old = FakeReport(package="com.a", manifest=None, findings=[])
    new = FakeReport(package="com.a", manifest=None, findings=[
        FakeFinding("Possible embedded secret: AWS", "x: AKIA...")])
    res = diff_reports(old, new)
    assert any(d.kind == "secret.added" for d in res.regressions())


# --- serialization & rendering --------------------------------------------

def test_to_dict_shape():
    res = diff_manifests(mk(), mk(debuggable=True))
    d = res.to_dict()
    for key in ("old_package", "new_package", "verdict", "risk_delta",
                "regression_count", "improvement_count", "deltas"):
        assert key in d
    assert d["verdict"] == "REGRESSED"
    assert d["regression_count"] >= 1


def test_delta_to_dict():
    d = Delta("x.y", REGRESSION, "detail", 7).to_dict()
    assert d == {"kind": "x.y", "classification": REGRESSION,
                 "detail": "detail", "weight": 7}


def test_render_text_regressed():
    out = render_text(diff_manifests(mk(), mk(debuggable=True)))
    assert "REGRESSED" in out
    assert "regressions" in out


def test_render_text_unchanged():
    out = render_text(diff_manifests(mk(), mk()))
    assert "no manifest-level changes" in out


def test_render_text_shows_risk_delta_sign():
    out = render_text(diff_manifests(mk(), mk(debuggable=True)))
    assert "+" in out  # positive risk delta rendered with sign
