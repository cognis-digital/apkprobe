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
