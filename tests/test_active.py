"""Tests for the authorization-gated ACTIVE acquisition mode.

These tests NEVER touch a real device or any network host. They drive
:class:`DeviceAcquirer` through an in-memory mock backend.
"""

from __future__ import annotations

import io

import pytest

from apkprobe.active import (
    ActiveConfig,
    ActiveError,
    AuthorizationError,
    ScopeError,
    DeviceAcquirer,
    RateLimiter,
    PullResult,
    validate_serial,
    validate_package,
    BANNER,
)


class MockBackend:
    """In-memory ADB stand-in. No subprocess, no socket, no device."""

    def __init__(self, devices=None, packages=None, paths=None):
        self._devices = list(devices or ["SERIAL123"])
        self._packages = dict(packages or {"SERIAL123": ["com.acme.app", "com.foo.bar"]})
        self._paths = dict(paths or {("SERIAL123", "com.acme.app"): ["/data/app/com.acme.app/base.apk"]})
        self.pulls = []

    def devices(self):
        return list(self._devices)

    def list_packages(self, serial):
        return list(self._packages.get(serial, []))

    def apk_paths(self, serial, package):
        return list(self._paths.get((serial, package), []))

    def pull(self, serial, remote_path, local_path):
        self.pulls.append((serial, remote_path, local_path))


def authorized_config(tmp_path, **kw):
    kw.setdefault("authorized", True)
    kw.setdefault("device_allowlist", ("SERIAL123",))
    kw.setdefault("rate_limit", 0)  # disable throttle in tests
    kw.setdefault("out_dir", str(tmp_path))
    return ActiveConfig(**kw)


def make_acq(tmp_path, backend=None, **cfg):
    backend = backend or MockBackend()
    return DeviceAcquirer(backend, authorized_config(tmp_path, **cfg),
                          banner_stream=io.StringIO()), backend


# -- the gate: OFF by default -----------------------------------------------

def test_default_config_is_not_authorized():
    assert ActiveConfig().authorized is False


def test_require_authorized_refuses_without_flag(tmp_path):
    cfg = ActiveConfig(authorized=False, device_allowlist=("SERIAL123",))
    with pytest.raises(AuthorizationError):
        cfg.require_authorized()


def test_require_authorized_refuses_without_allowlist():
    cfg = ActiveConfig(authorized=True, device_allowlist=())
    with pytest.raises(ScopeError):
        cfg.require_authorized()


def test_require_authorized_passes_when_gated():
    cfg = ActiveConfig(authorized=True, device_allowlist=("S",))
    cfg.require_authorized()  # no raise


def test_pull_refused_when_not_authorized(tmp_path):
    acq = DeviceAcquirer(MockBackend(),
                         ActiveConfig(authorized=False, device_allowlist=("SERIAL123",)),
                         banner_stream=io.StringIO())
    with pytest.raises(AuthorizationError):
        acq.pull_package("SERIAL123", "com.acme.app")


def test_list_packages_refused_when_not_authorized(tmp_path):
    acq = DeviceAcquirer(MockBackend(),
                         ActiveConfig(authorized=False),
                         banner_stream=io.StringIO())
    with pytest.raises(AuthorizationError):
        acq.list_packages("SERIAL123")


# -- scope enforcement ------------------------------------------------------

def test_in_scope():
    cfg = ActiveConfig(authorized=True, device_allowlist=("A", "B"))
    assert cfg.in_scope("A")
    assert cfg.in_scope("B")
    assert not cfg.in_scope("C")


def test_pull_refuses_out_of_scope_device(tmp_path):
    acq, _ = make_acq(tmp_path, device_allowlist=("SERIAL123",))
    with pytest.raises(ScopeError):
        acq.pull_package("OTHER", "com.acme.app")


def test_authorized_devices_filters_to_allowlist(tmp_path):
    backend = MockBackend(devices=["SERIAL123", "ROGUE"])
    acq, _ = make_acq(tmp_path, backend=backend, device_allowlist=("SERIAL123",))
    assert acq.authorized_devices() == ["SERIAL123"]


def test_authorized_devices_empty_when_none_match(tmp_path):
    backend = MockBackend(devices=["ROGUE"])
    acq, _ = make_acq(tmp_path, backend=backend, device_allowlist=("SERIAL123",))
    assert acq.authorized_devices() == []


def test_authorized_devices_requires_gate(tmp_path):
    acq = DeviceAcquirer(MockBackend(), ActiveConfig(authorized=False),
                         banner_stream=io.StringIO())
    with pytest.raises(AuthorizationError):
        acq.authorized_devices()


# -- happy path: pull --------------------------------------------------------

def test_pull_package_writes_local(tmp_path):
    acq, backend = make_acq(tmp_path)
    res = acq.pull_package("SERIAL123", "com.acme.app")
    assert isinstance(res, PullResult)
    assert res.serial == "SERIAL123"
    assert res.package == "com.acme.app"
    assert len(res.local_paths) == 1
    assert res.local_paths[0].endswith("com.acme.app.apk")
    assert len(backend.pulls) == 1


def test_pull_missing_package_errors(tmp_path):
    acq, _ = make_acq(tmp_path)
    with pytest.raises(ActiveError):
        acq.pull_package("SERIAL123", "com.not.here")


def test_pull_split_apks(tmp_path):
    paths = {("SERIAL123", "com.acme.app"): [
        "/data/app/base.apk", "/data/app/split_config.apk"]}
    backend = MockBackend(paths=paths)
    acq, _ = make_acq(tmp_path, backend=backend)
    res = acq.pull_package("SERIAL123", "com.acme.app")
    assert len(res.local_paths) == 2
    assert res.local_paths[0].endswith("com.acme.app.0.apk")
    assert res.local_paths[1].endswith("com.acme.app.1.apk")


def test_pull_emits_banner(tmp_path):
    stream = io.StringIO()
    backend = MockBackend()
    acq = DeviceAcquirer(backend, authorized_config(tmp_path), banner_stream=stream)
    acq.pull_package("SERIAL123", "com.acme.app")
    out = stream.getvalue()
    assert "AUTHORIZED USE ONLY" in out
    assert "SERIAL123" in out
    assert "com.acme.app" in out


def test_pull_result_to_dict(tmp_path):
    acq, _ = make_acq(tmp_path)
    d = acq.pull_package("SERIAL123", "com.acme.app").to_dict()
    assert d["serial"] == "SERIAL123"
    assert d["package"] == "com.acme.app"
    assert isinstance(d["local_paths"], list)
    assert isinstance(d["remote_paths"], list)


def test_list_packages_happy(tmp_path):
    acq, _ = make_acq(tmp_path)
    pkgs = acq.list_packages("SERIAL123")
    assert "com.acme.app" in pkgs


# -- input validation: no shell-arg smuggling -------------------------------

@pytest.mark.parametrize("serial", ["SERIAL123", "emulator-5554", "192.168.0.5:5555", "abc.def"])
def test_validate_serial_accepts(serial):
    assert validate_serial(serial) == serial


@pytest.mark.parametrize("serial", ["", "a b", "a;rm -rf", "a&b", "$(x)", "a|b", "../x", "a\nb"])
def test_validate_serial_rejects(serial):
    with pytest.raises(ScopeError):
        validate_serial(serial)


@pytest.mark.parametrize("pkg", ["com.acme.app", "a.b", "com.foo_bar.baz", "x1.y2.z3"])
def test_validate_package_accepts(pkg):
    assert validate_package(pkg) == pkg


@pytest.mark.parametrize("pkg", ["", "nodot", "com.", ".com", "com..x", "com.acme app",
                                  "com.acme;rm", "1bad.pkg", "com.acme/../x"])
def test_validate_package_rejects(pkg):
    with pytest.raises(ScopeError):
        validate_package(pkg)


def test_pull_rejects_bad_serial(tmp_path):
    acq, _ = make_acq(tmp_path, device_allowlist=("a;rm",))
    with pytest.raises(ScopeError):
        acq.pull_package("a;rm", "com.acme.app")


def test_pull_rejects_bad_package(tmp_path):
    acq, _ = make_acq(tmp_path)
    with pytest.raises(ScopeError):
        acq.pull_package("SERIAL123", "not_a_package")


def test_list_packages_filters_invalid(tmp_path):
    backend = MockBackend(packages={"SERIAL123": ["com.ok.app", "garbage", "also.fine"]})
    acq, _ = make_acq(tmp_path, backend=backend)
    pkgs = acq.list_packages("SERIAL123")
    assert "com.ok.app" in pkgs
    assert "also.fine" in pkgs
    assert "garbage" not in pkgs


# -- rate limiter ------------------------------------------------------------

def test_rate_limiter_sleeps_when_too_fast():
    slept = []
    clock = {"t": 0.0}
    rl = RateLimiter(rate=2.0, _sleep=lambda s: slept.append(s),
                     _now=lambda: clock["t"])
    rl.wait()       # first call: no sleep, sets last
    clock["t"] = 0.1
    rl.wait()       # 0.1s elapsed, interval 0.5s -> must sleep
    assert slept
    assert abs(slept[0] - 0.4) < 1e-6


def test_rate_limiter_zero_disables():
    slept = []
    rl = RateLimiter(rate=0, _sleep=lambda s: slept.append(s))
    rl.wait()
    rl.wait()
    assert slept == []


def test_rate_limiter_no_sleep_when_slow_enough():
    slept = []
    clock = {"t": 0.0}
    rl = RateLimiter(rate=10.0, _sleep=lambda s: slept.append(s),
                     _now=lambda: clock["t"])
    rl.wait()
    clock["t"] = 5.0   # way more than interval
    rl.wait()
    assert slept == []


def test_pull_honors_rate_limit(tmp_path):
    slept = []
    clock = {"t": 0.0}

    def now():
        return clock["t"]

    def sleep(s):
        slept.append(s)
        clock["t"] += s

    backend = MockBackend()
    limiter = RateLimiter(rate=5.0, _sleep=sleep, _now=now)
    acq = DeviceAcquirer(backend, authorized_config(tmp_path, rate_limit=5.0),
                         banner_stream=io.StringIO(), limiter=limiter)
    acq.pull_package("SERIAL123", "com.acme.app")
    # apk_paths + pull each call wait(); at least one throttle sleep occurred
    assert len(slept) >= 1


def test_banner_content():
    assert "AUTHORIZED USE ONLY" in BANNER
    assert "no exploitation" in BANNER.lower()
