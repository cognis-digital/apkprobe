"""Fixtures: build real binary AXML manifests and synthetic APK files."""

from __future__ import annotations

import io
import zipfile

import pytest

from tests._axml_fixture import encode


def manifest_tree(**app_attrs):
    """A representative manifest with overridable application attributes."""
    return {
        "tag": "manifest",
        "attrs": {"package": ("string", "com.acme.app"), "versionCode": ("int", 7)},
        "children": [
            {"tag": "uses-sdk", "attrs": {"minSdkVersion": ("int", 21), "targetSdkVersion": ("int", 33)}},
            {"tag": "uses-permission", "attrs": {"name": ("string", "android.permission.INTERNET")}},
            {"tag": "uses-permission", "attrs": {"name": ("string", "android.permission.READ_SMS")}},
            {
                "tag": "application",
                "attrs": {"label": ("string", "Acme"), **app_attrs},
                "children": [
                    {
                        "tag": "activity",
                        "attrs": {"name": ("string", ".MainActivity"), "exported": ("bool", True)},
                        "children": [{"tag": "intent-filter", "attrs": {}}],
                    },
                    {
                        "tag": "service",
                        "attrs": {"name": ("string", ".SyncService"), "exported": ("bool", True)},
                    },
                ],
            },
        ],
    }


@pytest.fixture
def manifest_axml() -> bytes:
    return encode(manifest_tree(
        debuggable=("bool", True),
        usesCleartextTraffic=("bool", True),
    ))


def build_apk(manifest_bytes: bytes, extra: dict | None = None, signed: bool = True) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_bytes)
        zf.writestr("resources.arsc", b"\x00\x00\x00\x00")
        if signed:
            zf.writestr("META-INF/CERT.RSA", b"\x30\x82fake-pkcs7")
            zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        for name, content in (extra or {}).items():
            zf.writestr(name, content)
    return buf.getvalue()


@pytest.fixture
def apk_path(tmp_path, manifest_axml) -> str:
    data = build_apk(
        manifest_axml,
        extra={"res/values/strings.xml": "<resources><string name=\"k\">AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI</string></resources>"},
    )
    p = tmp_path / "app.apk"
    p.write_bytes(data)
    return str(p)


def _benign_tree():
    """A minimal, hardened manifest: no debuggable/cleartext, guarded export."""
    return {
        "tag": "manifest",
        "attrs": {"package": ("string", "com.acme.app"), "versionCode": ("int", 6)},
        "children": [
            {"tag": "uses-sdk", "attrs": {"minSdkVersion": ("int", 28),
                                           "targetSdkVersion": ("int", 33)}},
            {"tag": "uses-permission",
             "attrs": {"name": ("string", "android.permission.INTERNET")}},
            {
                "tag": "application",
                "attrs": {"label": ("string", "Acme"),
                          "allowBackup": ("bool", False)},
                "children": [
                    {"tag": "activity",
                     "attrs": {"name": ("string", ".MainActivity"),
                               "exported": ("bool", False)}},
                ],
            },
        ],
    }


@pytest.fixture
def old_apk_path(tmp_path) -> str:
    """Baseline: hardened, no secrets."""
    data = build_apk(encode(_benign_tree()))
    p = tmp_path / "old.apk"
    p.write_bytes(data)
    return str(p)


@pytest.fixture
def new_apk_path(tmp_path, manifest_axml) -> str:
    """Candidate update: debuggable + cleartext + READ_SMS + embedded secret."""
    data = build_apk(
        manifest_axml,
        extra={"res/raw/cfg.json": "{\"k\":\"AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI\"}"},
    )
    p = tmp_path / "new.apk"
    p.write_bytes(data)
    return str(p)


# --- vuln-enrichment fixtures: an APK carrying real component evidence ------- #
# These names/coords are real, well-known vulnerable components; the advisories
# they map to live in the bundled OSV corpus. No fabricated data.
_LICENSES_BLOB = (
    "Third-party software notices\n"
    "----------------------------\n"
    "This application bundles:\n"
    "  org.apache.logging.log4j:log4j-core:2.14.1 "
    "(see CVE-2021-44228 / GHSA-jfh8-c2jp-5v3q)\n"
    "  com.fasterxml.jackson.core:jackson-databind:2.9.8\n"
    "  com.squareup.okhttp3:okhttp:3.12.0\n"
)
_PACKAGE_JSON = (
    '{"name":"acme-webview","version":"1.0.0",'
    '"dependencies":{"lodash":"4.17.4","axios":"0.18.0"}}'
)


@pytest.fixture
def vuln_apk_path(tmp_path, manifest_axml) -> str:
    """An APK whose resources name real vulnerable components + advisory ids."""
    data = build_apk(manifest_axml, extra={
        "assets/third_party_licenses.txt": _LICENSES_BLOB,
        "assets/www/js/lodash-4.17.4.min.js": "// lodash bundle",
        "assets/www/package.json": _PACKAGE_JSON,
        "lib/arm64-v8a/libsqlite.so": b"\x7fELFnative",
        "lib/armeabi-v7a/libc++_shared.so": b"\x7fELFskip",
    })
    p = tmp_path / "vuln.apk"
    p.write_bytes(data)
    return str(p)


@pytest.fixture
def clean_apk_path(tmp_path, manifest_axml) -> str:
    """An APK with no component evidence at all (no matches expected)."""
    data = build_apk(manifest_axml, extra={
        "res/values/strings.xml": "<resources><string name=\"x\">hello</string></resources>",
    })
    p = tmp_path / "clean.apk"
    p.write_bytes(data)
    return str(p)
