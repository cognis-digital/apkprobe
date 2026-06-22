"""Tests for the passive (offline) helpers: inventory + package-list triage."""

from __future__ import annotations

from apkprobe.manifest import AppManifest, Component
from apkprobe.passive import (
    component_inventory,
    triage_package_list,
    is_system_package,
    render_inventory,
    Inventory,
    ComponentRow,
    TriageHit,
)


def _manifest():
    m = AppManifest(package="com.acme.app")
    m.components = [
        Component("activity", ".Main", exported=True, has_permission=False, intent_filters=1),
        Component("service", ".Sync", exported=True, has_permission=True, intent_filters=0),
        Component("provider", ".Files", exported=False, has_permission=False, intent_filters=0),
        Component("receiver", ".Boot", exported=True, has_permission=False, intent_filters=2),
    ]
    return m


# -- inventory ---------------------------------------------------------------

def test_inventory_counts():
    inv = component_inventory(_manifest())
    assert isinstance(inv, Inventory)
    assert inv.package == "com.acme.app"
    assert len(inv.rows) == 4


def test_inventory_exported_unguarded():
    inv = component_inventory(_manifest())
    eu = inv.exported_unguarded
    names = {r.name for r in eu}
    assert names == {".Main", ".Boot"}   # .Sync is guarded, .Files not exported


def test_inventory_rows_are_componentrows():
    inv = component_inventory(_manifest())
    assert all(isinstance(r, ComponentRow) for r in inv.rows)


def test_inventory_to_dict():
    d = component_inventory(_manifest()).to_dict()
    assert d["package"] == "com.acme.app"
    assert d["total"] == 4
    assert d["exported_unguarded"] == 2
    assert len(d["components"]) == 4


def test_inventory_empty():
    inv = component_inventory(AppManifest(package="com.x"))
    assert inv.rows == []
    assert inv.exported_unguarded == []
    assert inv.to_dict()["total"] == 0


def test_render_inventory_text():
    txt = render_inventory(component_inventory(_manifest()))
    assert "com.acme.app" in txt
    assert ".Main" in txt
    assert "exported" in txt
    assert "guarded" in txt
    assert "intent-filter" in txt


def test_render_inventory_unknown_package():
    txt = render_inventory(component_inventory(AppManifest()))
    assert "(unknown)" in txt


# -- system package detection -----------------------------------------------

def test_is_system_package_android():
    assert is_system_package("android")
    assert is_system_package("com.android.settings")
    assert is_system_package("com.google.android.gms")
    assert is_system_package("org.chromium.webview")


def test_is_system_package_third_party():
    assert not is_system_package("com.acme.app")
    assert not is_system_package("com.facebook.katana")
    assert not is_system_package("androidx.something")  # not the 'android' pkg


def test_is_system_package_whitespace():
    assert is_system_package("  android  ")


# -- triage ------------------------------------------------------------------

def test_triage_flags_suspicious_names():
    hits = triage_package_list(["com.acme.app", "com.evil.spytool", "com.x.cleaner"])
    flagged = {h.package for h in hits}
    assert "com.evil.spytool" in flagged
    assert "com.x.cleaner" in flagged
    assert "com.acme.app" not in flagged


def test_triage_returns_triagehits():
    hits = triage_package_list(["com.x.hack"])
    assert hits and isinstance(hits[0], TriageHit)
    assert "hack" in hits[0].reason


def test_triage_strips_package_prefix():
    hits = triage_package_list(["package:com.x.booster"])
    assert hits[0].package == "com.x.booster"


def test_triage_skips_system_by_default():
    hits = triage_package_list(["com.android.cleaner"])  # system + suspicious word
    assert hits == []


def test_triage_includes_system_when_asked():
    hits = triage_package_list(["com.android.cleaner"], include_system=True)
    assert any(h.package == "com.android.cleaner" for h in hits)


def test_triage_respects_allowlist():
    hits = triage_package_list(["com.corp.cleaner"], allowlist=["com.corp.cleaner"])
    assert hits == []


def test_triage_ignores_blank_lines():
    hits = triage_package_list(["", "   ", "com.x.spy"])
    assert len(hits) == 1


def test_triage_clean_list():
    hits = triage_package_list(["com.acme.app", "com.foo.bar", "com.baz.qux"])
    assert hits == []


def test_triage_hit_to_dict():
    h = triage_package_list(["com.x.tracker"])[0]
    d = h.to_dict()
    assert d["package"] == "com.x.tracker"
    assert "reason" in d


def test_triage_one_hit_per_package():
    # a name matching two needles still yields a single hit
    hits = triage_package_list(["com.x.modloader"])
    assert len(hits) == 1
