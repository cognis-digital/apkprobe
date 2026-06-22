"""CLI-level tests for inventory/triage (passive) and pull (active, gated)."""

from __future__ import annotations

import json

import pytest

from apkprobe import cli


def run(argv, capsys):
    rc = cli.main(argv)
    out = capsys.readouterr()
    return rc, out.out, out.err


# -- inventory ---------------------------------------------------------------

def test_inventory_table(apk_path, capsys):
    rc, out, _ = run(["inventory", apk_path], capsys)
    assert rc == 0
    assert "com.acme.app" in out
    assert "components:" in out


def test_inventory_json(apk_path, capsys):
    rc, out, _ = run(["inventory", apk_path, "--json"], capsys)
    assert rc == 0
    data = json.loads(out)
    assert data["package"] == "com.acme.app"
    assert "components" in data


def test_inventory_bad_path(tmp_path, capsys):
    rc, _, err = run(["inventory", str(tmp_path / "nope.apk")], capsys)
    assert rc == 1
    assert "error" in err


# -- triage ------------------------------------------------------------------

def test_triage_table(tmp_path, capsys):
    f = tmp_path / "pkgs.txt"
    f.write_text("package:com.acme.app\npackage:com.evil.spytool\n", encoding="utf-8")
    rc, out, _ = run(["triage", str(f)], capsys)
    assert rc == 0
    assert "com.evil.spytool" in out
    assert "hit" in out


def test_triage_json(tmp_path, capsys):
    f = tmp_path / "pkgs.txt"
    f.write_text("com.x.cleaner\ncom.acme.app\n", encoding="utf-8")
    rc, out, _ = run(["triage", str(f), "--json"], capsys)
    assert rc == 0
    data = json.loads(out)
    assert any(h["package"] == "com.x.cleaner" for h in data)


def test_triage_allow(tmp_path, capsys):
    f = tmp_path / "pkgs.txt"
    f.write_text("com.corp.cleaner\n", encoding="utf-8")
    rc, out, _ = run(["triage", str(f), "--allow", "com.corp.cleaner", "--json"], capsys)
    assert rc == 0
    assert json.loads(out) == []


def test_triage_missing_file(tmp_path, capsys):
    rc, _, err = run(["triage", str(tmp_path / "nope.txt")], capsys)
    assert rc == 1
    assert "error" in err


# -- scan --emit-manifest (port contract) -----------------------------------

def test_emit_manifest(apk_path, capsys):
    rc, out, _ = run(["scan", apk_path, "--emit-manifest"], capsys)
    assert rc == 0
    data = json.loads(out)
    assert data["package"] == "com.acme.app"
    assert "components" in data
    assert "uses_cleartext_traffic" in data


# -- pull: the authorization gate -------------------------------------------

def test_pull_refused_without_authorized(capsys):
    rc, _, err = run(["pull", "com.acme.app"], capsys)
    assert rc == 2
    assert "active mode is OFF by default" in err


def test_pull_refused_without_allowlist(capsys):
    rc, _, err = run(["pull", "com.acme.app", "--authorized"], capsys)
    assert rc == 2
    assert "allowlist" in err


def test_pull_no_device_connected(capsys, monkeypatch):
    # Authorized + allowlisted, but the (real) adb backend reports no devices.
    import apkprobe.active as active

    class EmptyBackend:
        def devices(self): return []
        def list_packages(self, s): return []
        def apk_paths(self, s, p): return []
        def pull(self, s, r, l): pass

    monkeypatch.setattr(active, "AdbCliBackend", lambda adb="adb": EmptyBackend())
    rc, _, err = run(["pull", "com.acme.app", "--authorized",
                      "--device-allowlist", "SERIAL123"], capsys)
    assert rc == 1
    assert "no authorized device" in err


def test_pull_happy_path_with_mock_backend(tmp_path, capsys, monkeypatch):
    import apkprobe.active as active

    class Backend:
        def devices(self): return ["SERIAL123"]
        def list_packages(self, s): return ["com.acme.app"]
        def apk_paths(self, s, p): return ["/data/app/base.apk"]
        def pull(self, s, r, l):
            with open(l, "wb") as fh:
                fh.write(b"PK\x03\x04")

    monkeypatch.setattr(active, "AdbCliBackend", lambda adb="adb": Backend())
    rc, out, _ = run(["pull", "com.acme.app", "--authorized",
                      "--device-allowlist", "SERIAL123",
                      "--rate-limit", "0", "--out-dir", str(tmp_path),
                      "--json"], capsys)
    assert rc == 0
    data = json.loads(out)
    assert data[0]["package"] == "com.acme.app"
    assert data[0]["serial"] == "SERIAL123"


def test_pull_out_of_scope_device(tmp_path, capsys, monkeypatch):
    import apkprobe.active as active

    class Backend:
        def devices(self): return ["ROGUE"]
        def list_packages(self, s): return []
        def apk_paths(self, s, p): return ["/x.apk"]
        def pull(self, s, r, l): pass

    monkeypatch.setattr(active, "AdbCliBackend", lambda adb="adb": Backend())
    # explicit --device not on allowlist
    rc, _, err = run(["pull", "com.acme.app", "--authorized",
                      "--device-allowlist", "SERIAL123",
                      "--device", "ROGUE", "--rate-limit", "0"], capsys)
    assert rc == 2
    assert "not in the authorized allowlist" in err
