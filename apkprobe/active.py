"""Authorization-gated ACTIVE acquisition from a CONNECTED device you own.

apkprobe is a **defensive, static** tool. Everything else in the package is
passive: you hand it an ``.apk`` file already in your possession and it reads
bytes off disk — no device, no network, no side effects.

This module adds a strictly-bounded **active** capability: pulling the installed
APK of a package off a device **physically connected to this host** (via ADB),
so it can then be analyzed by the normal passive pipeline. There is no
exploitation, no payload, no remote target — only "read an app you own off a
device you own".

Because it touches a real device, it is gated hard:

* **OFF by default.** Nothing here runs unless the caller passes
  ``--authorized`` (CLI) / ``authorized=True`` (API).
* **Device allowlist required.** The caller MUST name the device serial(s) it
  is authorized to touch (``--device-allowlist``). A device whose serial is not
  on the allowlist is refused; we never act on "whatever happens to be plugged
  in".
* **Rate limited.** Pulls are throttled (``--rate-limit`` ops/sec) so the tool
  can never hammer a device.
* **Loud banner.** Every active run prints an authorized-use-only banner naming
  the device and package, to stderr, before doing anything.
* **Localhost transport only.** ADB talks to a local daemon over the loopback
  interface; this module never opens a socket to an external host.

Tests drive this through a pluggable :class:`AdbBackend`; CI never touches a
real device or any external host.
"""

from __future__ import annotations

import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Protocol

BANNER = (
    "================================================================\n"
    " apkprobe ACTIVE mode — AUTHORIZED USE ONLY\n"
    " Pull an installed app off a device you own / are authorized to\n"
    " assess. Defensive acquisition only: no exploitation, no payload.\n"
    " You are responsible for having authorization for every device.\n"
    "================================================================"
)

# ADB serials are vendor-defined but in practice are a bounded set of safe
# characters. We refuse anything outside this set so a serial can never smuggle
# a shell argument into a command line.
_SERIAL_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
# Android package names: dotted segments of identifier characters.
_PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")


class ActiveError(RuntimeError):
    """Active acquisition was refused or failed."""


class AuthorizationError(ActiveError):
    """Active mode was invoked without the required authorization gate."""


class ScopeError(ActiveError):
    """A device or package outside the authorized scope was requested."""


def validate_serial(serial: str) -> str:
    if not serial or not _SERIAL_RE.match(serial):
        raise ScopeError(f"invalid device serial: {serial!r}")
    return serial


def validate_package(pkg: str) -> str:
    if not pkg or not _PKG_RE.match(pkg):
        raise ScopeError(f"invalid package name: {pkg!r}")
    return pkg


class AdbBackend(Protocol):
    """Minimal device transport. The real one shells out to ``adb`` over the
    loopback ADB daemon; tests supply a mock. No method ever touches an
    external host."""

    def devices(self) -> list[str]:
        """Return the serials of currently-connected devices."""
        ...

    def list_packages(self, serial: str) -> list[str]:
        """Return installed package names on ``serial``."""
        ...

    def apk_paths(self, serial: str, package: str) -> list[str]:
        """Return the on-device APK path(s) for ``package`` (split APKs allowed)."""
        ...

    def pull(self, serial: str, remote_path: str, local_path: str) -> None:
        """Copy ``remote_path`` off ``serial`` to ``local_path`` on this host."""
        ...


@dataclass
class RateLimiter:
    """Token-style throttle: at most ``rate`` operations per second."""

    rate: float = 1.0
    _sleep: Callable[[float], None] = time.sleep
    _now: Callable[[], float] = time.monotonic
    _last: float = field(default=0.0)
    _fired: bool = field(default=False)

    def wait(self) -> None:
        if self.rate <= 0:
            return
        interval = 1.0 / self.rate
        now = self._now()
        if self._fired:
            elapsed = now - self._last
            if elapsed < interval:
                self._sleep(interval - elapsed)
        self._fired = True
        self._last = self._now()


@dataclass
class ActiveConfig:
    authorized: bool = False
    device_allowlist: tuple[str, ...] = ()
    rate_limit: float = 1.0
    out_dir: str = "."

    def require_authorized(self) -> None:
        if not self.authorized:
            raise AuthorizationError(
                "active mode is OFF by default; pass --authorized to confirm you "
                "are authorized to pull from the named device(s)"
            )
        if not self.device_allowlist:
            raise ScopeError(
                "active mode requires an explicit --device-allowlist of the "
                "device serial(s) you are authorized to touch"
            )

    def in_scope(self, serial: str) -> bool:
        return serial in self.device_allowlist


@dataclass
class PullResult:
    serial: str
    package: str
    local_paths: list[str] = field(default_factory=list)
    remote_paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "serial": self.serial,
            "package": self.package,
            "local_paths": list(self.local_paths),
            "remote_paths": list(self.remote_paths),
        }


class DeviceAcquirer:
    """Authorization-gated front door for active acquisition.

    Construct with a backend (real or mock) and an :class:`ActiveConfig`. Every
    public method enforces the gate before touching the backend.
    """

    def __init__(
        self,
        backend: AdbBackend,
        config: ActiveConfig,
        *,
        banner_stream=sys.stderr,
        limiter: Optional[RateLimiter] = None,
    ):
        self.backend = backend
        self.config = config
        self._banner_stream = banner_stream
        self._limiter = limiter or RateLimiter(rate=config.rate_limit)

    # -- gate helpers -----------------------------------------------------

    def _gate(self, serial: str) -> str:
        self.config.require_authorized()
        validate_serial(serial)
        if not self.config.in_scope(serial):
            raise ScopeError(
                f"device {serial!r} is not in the authorized allowlist "
                f"{list(self.config.device_allowlist)!r}; refusing"
            )
        return serial

    def _emit_banner(self, serial: str, package: str) -> None:
        if self._banner_stream is not None:
            print(BANNER, file=self._banner_stream)
            print(f" device:  {serial}\n package: {package}", file=self._banner_stream)

    # -- operations -------------------------------------------------------

    def authorized_devices(self) -> list[str]:
        """Connected devices that are ALSO on the allowlist (the only ones we
        will ever act on)."""
        self.config.require_authorized()
        connected = [validate_serial(s) for s in self.backend.devices()]
        return [s for s in connected if self.config.in_scope(s)]

    def list_packages(self, serial: str) -> list[str]:
        self._gate(serial)
        self._limiter.wait()
        return [validate_package(p) for p in self.backend.list_packages(serial)
                if _PKG_RE.match(p)]

    def pull_package(self, serial: str, package: str) -> PullResult:
        self._gate(serial)
        validate_package(package)
        self._emit_banner(serial, package)

        os.makedirs(self.config.out_dir, exist_ok=True)
        self._limiter.wait()
        remotes = list(self.backend.apk_paths(serial, package))
        if not remotes:
            raise ActiveError(f"package {package!r} not found on device {serial!r}")

        result = PullResult(serial=serial, package=package, remote_paths=remotes)
        for idx, remote in enumerate(remotes):
            suffix = "" if len(remotes) == 1 else f".{idx}"
            local = os.path.join(self.config.out_dir, f"{package}{suffix}.apk")
            self._limiter.wait()
            self.backend.pull(serial, remote, local)
            result.local_paths.append(local)
        return result


# ---------------------------------------------------------------------------
# Real backend: shells out to the locally-installed ``adb`` binary. Never
# imported in tests — tests use a mock backend. The ADB daemon it talks to is a
# local loopback service; we never connect to an external host.
# ---------------------------------------------------------------------------

class AdbCliBackend:  # pragma: no cover - exercised only against a real device
    def __init__(self, adb: str = "adb"):
        self.adb = adb

    def _run(self, args: list[str], capture: bool = True) -> str:
        import subprocess
        proc = subprocess.run(
            [self.adb, *args],
            check=True,
            capture_output=capture,
            text=True,
            timeout=120,
        )
        return proc.stdout if capture else ""

    def devices(self) -> list[str]:
        out = self._run(["devices"])
        serials: list[str] = []
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line or "\t" not in line:
                continue
            serial, state = line.split("\t", 1)
            if state.strip() == "device":
                serials.append(serial.strip())
        return serials

    def list_packages(self, serial: str) -> list[str]:
        out = self._run(["-s", serial, "shell", "pm", "list", "packages"])
        return [ln.split(":", 1)[1].strip() for ln in out.splitlines()
                if ln.startswith("package:")]

    def apk_paths(self, serial: str, package: str) -> list[str]:
        out = self._run(["-s", serial, "shell", "pm", "path", package])
        return [ln.split(":", 1)[1].strip() for ln in out.splitlines()
                if ln.startswith("package:")]

    def pull(self, serial: str, remote_path: str, local_path: str) -> None:
        self._run(["-s", serial, "pull", remote_path, local_path], capture=False)
