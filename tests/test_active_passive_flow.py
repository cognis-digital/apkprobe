"""Integration: an authorized active pull of a fixture APK feeds the passive
scanner. Uses a mock backend that 'pulls' a bundled APK fixture — no real
device, no network."""

from __future__ import annotations

import io
import shutil

from apkprobe.active import ActiveConfig, DeviceAcquirer
from apkprobe.analyzer import analyze_apk


class FixtureBackend:
    """Mock device that 'pulls' by copying a local fixture APK into place."""

    def __init__(self, fixture_apk: str):
        self.fixture = fixture_apk

    def devices(self):
        return ["LABDEVICE01"]

    def list_packages(self, serial):
        return ["com.acme.app"]

    def apk_paths(self, serial, package):
        return ["/data/app/com.acme.app/base.apk"]

    def pull(self, serial, remote_path, local_path):
        shutil.copyfile(self.fixture, local_path)


def test_pull_then_scan(apk_path, tmp_path):
    cfg = ActiveConfig(authorized=True, device_allowlist=("LABDEVICE01",),
                       rate_limit=0, out_dir=str(tmp_path))
    acq = DeviceAcquirer(FixtureBackend(apk_path), cfg, banner_stream=io.StringIO())

    result = acq.pull_package("LABDEVICE01", "com.acme.app")
    assert len(result.local_paths) == 1

    # Pulled APK flows straight into the normal passive pipeline.
    report = analyze_apk(result.local_paths[0])
    assert report.package == "com.acme.app"
    # The fixture is debuggable + cleartext + has an embedded secret.
    titles = [f.title for f in report.findings]
    assert "Application is debuggable" in titles
    assert any("embedded secret" in t for t in titles)


def test_authorized_devices_then_list(apk_path, tmp_path):
    cfg = ActiveConfig(authorized=True, device_allowlist=("LABDEVICE01",),
                       rate_limit=0, out_dir=str(tmp_path))
    acq = DeviceAcquirer(FixtureBackend(apk_path), cfg, banner_stream=io.StringIO())
    assert acq.authorized_devices() == ["LABDEVICE01"]
    assert "com.acme.app" in acq.list_packages("LABDEVICE01")
