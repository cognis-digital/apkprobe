"""Tests for the attack-surface profiling / risk-scoring engine."""

from __future__ import annotations

import pytest

from apkprobe.manifest import AppManifest, Component
from apkprobe.attacksurface import (
    profile, render_text, PERMISSION_KB, PermInfo, AttackSurface,
    CapabilityHit, ExposedComponent, _grade, V_NETWORK,
)


def mk(**kw) -> AppManifest:
    m = AppManifest(package=kw.pop("package", "com.test.app"))
    for k, v in kw.items():
        setattr(m, k, v)
    return m


# --- knowledge-base integrity ---------------------------------------------

def test_kb_nonempty():
    assert len(PERMISSION_KB) >= 20


@pytest.mark.parametrize("perm,info", list(PERMISSION_KB.items()))
def test_kb_entries_are_well_formed(perm, info):
    assert perm.startswith("android.permission.")
    assert isinstance(info, PermInfo)
    assert 1 <= info.weight <= 10
    assert info.capability
    assert info.vector
    assert info.note


def test_kb_weights_bounded():
    assert all(1 <= i.weight <= 10 for i in PERMISSION_KB.values())


def test_kb_high_risk_perms_present():
    for p in (
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_SMS",
    ):
        assert p in PERMISSION_KB
        assert PERMISSION_KB[p].weight >= 8


# --- grading bands --------------------------------------------------------

@pytest.mark.parametrize("score,grade", [
    (0, "A"), (5, "A"), (14, "A"),
    (15, "B"), (29, "B"),
    (30, "C"), (44, "C"),
    (45, "D"), (59, "D"),
    (60, "E"), (79, "E"),
    (80, "F"), (100, "F"),
])
def test_grade_bands(score, grade):
    assert _grade(score) == grade


# --- empty / benign manifest ----------------------------------------------

def test_empty_manifest_scores_zero():
    surf = profile(mk(allow_backup=False))
    assert surf.score == 0
    assert surf.grade == "A"
    assert surf.capabilities == []
    assert surf.exposed_components == []


def test_default_allow_backup_adds_points():
    # AppManifest default allow_backup=True
    surf = profile(mk())
    assert any(r == "adb-backup-allowed" for r, _ in surf.score_breakdown)


# --- capability mapping ---------------------------------------------------

def test_known_permission_maps_to_capability():
    surf = profile(mk(permissions=["android.permission.RECORD_AUDIO"],
                      allow_backup=False))
    caps = {c.permission: c for c in surf.capabilities}
    assert "android.permission.RECORD_AUDIO" in caps
    assert caps["android.permission.RECORD_AUDIO"].capability == "Microphone capture"
    assert caps["android.permission.RECORD_AUDIO"].vector.startswith("surveillance")


def test_unknown_permission_goes_to_unknown_list():
    surf = profile(mk(permissions=["com.example.CUSTOM_PERM"], allow_backup=False))
    assert "com.example.CUSTOM_PERM" in surf.unknown_permissions
    assert surf.capabilities == []


def test_duplicate_permissions_counted_once():
    surf = profile(mk(
        permissions=["android.permission.CAMERA", "android.permission.CAMERA"],
        allow_backup=False))
    assert len(surf.capabilities) == 1


def test_capabilities_sorted_by_weight_desc():
    surf = profile(mk(permissions=[
        "android.permission.INTERNET",          # weight 1
        "android.permission.RECORD_AUDIO",      # weight 9
        "android.permission.READ_CONTACTS",     # weight 6
    ], allow_backup=False))
    weights = [c.weight for c in surf.capabilities]
    assert weights == sorted(weights, reverse=True)


def test_permission_points_capped_at_50():
    # request every catalogued permission -> total raw weight > 50
    surf = profile(mk(permissions=list(PERMISSION_KB.keys()), allow_backup=False))
    perm_pts = dict(surf.score_breakdown).get("requested-capabilities", 0)
    assert perm_pts == 50


def test_vector_diversity_bonus_multi():
    surf = profile(mk(permissions=[
        "android.permission.ACCESS_FINE_LOCATION",   # location
        "android.permission.RECORD_AUDIO",           # audio
        "android.permission.READ_SMS",               # messaging
        "android.permission.READ_CONTACTS",          # pii
    ], allow_backup=False))
    assert dict(surf.score_breakdown).get("multi-vector-capability") == 6


def test_vector_diversity_bonus_three():
    surf = profile(mk(permissions=[
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_SMS",
    ], allow_backup=False))
    assert dict(surf.score_breakdown).get("multi-vector-capability") == 3


def test_network_not_counted_in_vector_diversity():
    surf = profile(mk(permissions=[
        "android.permission.INTERNET",
        "android.permission.CAMERA",
    ], allow_backup=False))
    # only one non-network distinct vector -> no diversity bonus
    assert "multi-vector-capability" not in dict(surf.score_breakdown)


def test_vectors_view_groups_capabilities():
    surf = profile(mk(permissions=[
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
    ], allow_backup=False))
    v = surf.vectors()
    loc = [k for k in v if k.startswith("surveillance:location")]
    assert loc
    assert len(v[loc[0]]) == 2


# --- IPC / exported components --------------------------------------------

def comp(kind, name, exported=True, perm=False, filters=0):
    return Component(kind=kind, name=name, exported=exported,
                     has_permission=perm, intent_filters=filters)


def test_unguarded_exported_component_adds_points():
    surf = profile(mk(components=[comp("activity", ".A")], allow_backup=False))
    assert dict(surf.score_breakdown).get("unguarded-exported-components") == 3
    assert len(surf.unguarded_components()) == 1


def test_guarded_component_no_points():
    surf = profile(mk(components=[comp("activity", ".A", perm=True)],
                      allow_backup=False))
    assert "unguarded-exported-components" not in dict(surf.score_breakdown)
    assert surf.unguarded_components() == []


def test_non_exported_component_ignored():
    surf = profile(mk(components=[comp("activity", ".A", exported=False)],
                      allow_backup=False))
    assert surf.exposed_components == []


def test_provider_weighs_extra():
    a = profile(mk(components=[comp("activity", ".A")], allow_backup=False))
    p = profile(mk(components=[comp("provider", ".P")], allow_backup=False))
    pa = dict(a.score_breakdown)["unguarded-exported-components"]
    pp = dict(p.score_breakdown)["unguarded-exported-components"]
    assert pp > pa  # provider gets +2 extra


def test_ipc_points_capped():
    comps = [comp("activity", f".A{i}") for i in range(20)]
    surf = profile(mk(components=comps, allow_backup=False))
    assert dict(surf.score_breakdown)["unguarded-exported-components"] == 18


# --- config flags ---------------------------------------------------------

def test_debuggable_adds_12():
    surf = profile(mk(debuggable=True, allow_backup=False))
    assert dict(surf.score_breakdown).get("debuggable") == 12


def test_cleartext_adds_8():
    surf = profile(mk(uses_cleartext_traffic=True, allow_backup=False))
    assert dict(surf.score_breakdown).get("cleartext-traffic") == 8


def test_cleartext_none_not_counted():
    surf = profile(mk(uses_cleartext_traffic=None, allow_backup=False))
    assert "cleartext-traffic" not in dict(surf.score_breakdown)


def test_low_min_sdk_adds_points():
    surf = profile(mk(min_sdk=19, allow_backup=False))
    assert dict(surf.score_breakdown).get("low-min-sdk") == 4


def test_high_min_sdk_no_points():
    surf = profile(mk(min_sdk=30, allow_backup=False))
    assert "low-min-sdk" not in dict(surf.score_breakdown)


# --- score bounds & determinism -------------------------------------------

def test_score_never_exceeds_100():
    surf = profile(mk(
        permissions=list(PERMISSION_KB.keys()),
        components=[comp("provider", f".P{i}") for i in range(20)],
        debuggable=True, uses_cleartext_traffic=True, allow_backup=True,
        min_sdk=16))
    assert surf.score == 100
    assert surf.grade == "F"


def test_profile_is_deterministic():
    args = dict(permissions=["android.permission.CAMERA",
                             "android.permission.READ_SMS"],
                components=[comp("activity", ".A")], debuggable=True)
    a = profile(mk(**args)).to_dict()
    b = profile(mk(**args)).to_dict()
    assert a == b


def test_breakdown_sums_to_score_when_under_cap():
    surf = profile(mk(permissions=["android.permission.CAMERA"],
                      debuggable=True, allow_backup=False))
    assert sum(p for _, p in surf.score_breakdown) == surf.score


# --- serialization & rendering --------------------------------------------

def test_to_dict_shape():
    surf = profile(mk(permissions=["android.permission.READ_SMS"],
                      components=[comp("activity", ".A")], debuggable=True))
    d = surf.to_dict()
    for key in ("package", "score", "grade", "score_breakdown", "flags",
                "vectors", "capabilities", "unknown_permissions",
                "exposed_components"):
        assert key in d
    assert isinstance(d["score"], int)
    assert d["grade"] in ("A", "B", "C", "D", "E", "F")


def test_to_dict_flags_populated():
    d = profile(mk(debuggable=True, min_sdk=21, target_sdk=33)).to_dict()
    assert d["flags"]["debuggable"] is True
    assert d["flags"]["min_sdk"] == 21
    assert d["flags"]["target_sdk"] == 33


def test_render_text_contains_score_and_grade():
    out = render_text(profile(mk(permissions=["android.permission.CAMERA"],
                                 debuggable=True)))
    assert "risk score:" in out
    assert "grade" in out
    assert "debuggable" in out


def test_render_text_lists_capabilities():
    out = render_text(profile(mk(permissions=["android.permission.RECORD_AUDIO"],
                                 allow_backup=False)))
    assert "Microphone capture" in out


def test_render_text_lists_exported_surface():
    out = render_text(profile(mk(components=[comp("activity", ".Main", filters=1)],
                                 allow_backup=False)))
    assert "UNGUARDED" in out
    assert ".Main" in out


def test_render_text_lists_unknown_perms():
    out = render_text(profile(mk(permissions=["com.x.CUSTOM"], allow_backup=False)))
    assert "uncatalogued permissions" in out
    assert "com.x.CUSTOM" in out


def test_render_empty_profile():
    out = render_text(profile(mk(allow_backup=False)))
    assert "0/100" in out
