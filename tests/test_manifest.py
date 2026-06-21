from apkprobe.manifest import AppManifest
from tests._axml_fixture import encode
from tests.conftest import manifest_tree


def test_parse_core_fields():
    m = AppManifest.from_axml(encode(manifest_tree(debuggable=("bool", True))))
    assert m.package == "com.acme.app"
    assert m.version_code == "7"
    assert m.min_sdk == 21
    assert m.target_sdk == 33
    assert m.debuggable is True


def test_permissions_collected():
    m = AppManifest.from_axml(encode(manifest_tree()))
    assert "android.permission.INTERNET" in m.permissions
    assert "android.permission.READ_SMS" in m.permissions


def test_components_and_exported():
    m = AppManifest.from_axml(encode(manifest_tree()))
    kinds = {c.kind for c in m.components}
    assert {"activity", "service"} <= kinds
    activity = next(c for c in m.components if c.kind == "activity")
    assert activity.exported is True
    assert activity.intent_filters == 1


def test_allow_backup_defaults_true():
    m = AppManifest.from_axml(encode(manifest_tree()))
    assert m.allow_backup is True  # Android default when unset


def test_cleartext_tri_state():
    m_unset = AppManifest.from_axml(encode(manifest_tree()))
    assert m_unset.uses_cleartext_traffic is None
    m_set = AppManifest.from_axml(encode(manifest_tree(usesCleartextTraffic=("bool", True))))
    assert m_set.uses_cleartext_traffic is True
