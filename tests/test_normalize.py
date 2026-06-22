"""Tests for the normalized-manifest contract shared with the language ports."""

from __future__ import annotations

import json

from apkprobe.manifest import AppManifest, Component
from apkprobe.normalize import normalize_manifest, normalize_manifest_json
from apkprobe.rules import analyze_manifest


def _rich():
    m = AppManifest(package="com.acme.app", min_sdk=21, target_sdk=33,
                    debuggable=True, allow_backup=True, uses_cleartext_traffic=True)
    m.permissions = ["android.permission.READ_SMS", "android.permission.CAMERA"]
    m.components = [
        Component("activity", ".Main", True, False, 1),
        Component("service", ".Sync", True, True, 0),
    ]
    return m


def test_normalize_keys():
    d = normalize_manifest(_rich())
    assert set(d) == {
        "package", "min_sdk", "target_sdk", "debuggable", "allow_backup",
        "uses_cleartext_traffic", "network_security_config", "permissions",
        "components",
    }


def test_normalize_values():
    d = normalize_manifest(_rich())
    assert d["package"] == "com.acme.app"
    assert d["min_sdk"] == 21
    assert d["target_sdk"] == 33
    assert d["debuggable"] is True
    assert d["uses_cleartext_traffic"] is True
    assert d["permissions"] == ["android.permission.READ_SMS", "android.permission.CAMERA"]


def test_normalize_cleartext_unset_is_null():
    m = AppManifest(package="com.x")
    d = normalize_manifest(m)
    assert d["uses_cleartext_traffic"] is None


def test_normalize_cleartext_false():
    m = AppManifest(package="com.x", uses_cleartext_traffic=False)
    assert normalize_manifest(m)["uses_cleartext_traffic"] is False


def test_normalize_components_shape():
    d = normalize_manifest(_rich())
    c = d["components"][0]
    assert set(c) == {"kind", "name", "exported", "has_permission", "intent_filters"}
    assert c["kind"] == "activity"
    assert c["intent_filters"] == 1


def test_normalize_json_roundtrips():
    s = normalize_manifest_json(_rich())
    again = json.loads(s)
    assert again["package"] == "com.acme.app"


def test_normalize_json_compact():
    s = normalize_manifest_json(AppManifest(package="com.x"), indent=None)
    assert "\n" not in s


# Golden finding set the ports must reproduce from the same normalized JSON.
GOLDEN_TITLES = [
    "Application is debuggable",
    "ADB backup allowed",
    "Cleartext (HTTP) traffic permitted",
    "No Network Security Config",
    "Exported activity without permission: .Main",
    "Sensitive permission requested: android.permission.CAMERA",
    "Sensitive permission requested: android.permission.READ_SMS",
    "Low minSdkVersion (21)",
]


def test_golden_finding_set_for_ports():
    findings = analyze_manifest(_rich())
    assert [f.title for f in findings] == GOLDEN_TITLES


def test_guarded_service_not_in_golden():
    titles = [f.title for f in analyze_manifest(_rich())]
    assert "Exported service without permission: .Sync" not in titles
