"""Passive (offline, no-network, no-device) analysis helpers.

This is apkprobe's safe default mode. Everything here operates on bytes you
already have — an ``.apk`` file on disk, or an offline inventory/SBOM-style list
of installed packages exported earlier. Nothing in this module opens a network
socket or touches a device.

It complements the per-file scan (``rules.py`` / ``analyzer.py``) with:

* :func:`component_inventory` — a flat, defender-readable inventory of the IPC
  surface (exported components, permission guards, intent-filter counts);
* :func:`triage_package_list` — offline triage of a captured package list
  (e.g. a ``pm list packages`` dump saved to a file), flagging packages that
  match a known-sensitive/sideload-risk heuristic set, with **no fabricated
  intel** — only name-shape heuristics and a documented allow/deny set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .manifest import AppManifest, Component

# Documented platform-package prefixes that are expected on a stock device and
# therefore low-interest for a sideload/triage pass. Not "intel" — just the
# Android system namespace.
# Exact platform package names that are not dotted prefixes.
_SYSTEM_EXACT = ("android",)
_SYSTEM_PREFIXES = (
    "com.android.",
    "com.google.android.",
    "com.qualcomm.",
    "org.chromium.",
)

# Name-shape heuristics for packages worth a second look in an offline triage.
# These are heuristics over the package NAME only; they assert nothing about the
# code and fabricate no CVE/intel.
_SUSPICIOUS_SUBSTRINGS = (
    "cleaner",
    "booster",
    "spy",
    "tracker",
    "hack",
    "mod",
    "crack",
    "loader",
)


@dataclass
class ComponentRow:
    kind: str
    name: str
    exported: bool
    guarded: bool
    intent_filters: int

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Inventory:
    package: str
    rows: list[ComponentRow] = field(default_factory=list)

    @property
    def exported_unguarded(self) -> list[ComponentRow]:
        return [r for r in self.rows if r.exported and not r.guarded]

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "components": [r.to_dict() for r in self.rows],
            "exported_unguarded": len(self.exported_unguarded),
            "total": len(self.rows),
        }


def component_inventory(manifest: AppManifest) -> Inventory:
    """Flatten a parsed manifest's components into an inventory (offline)."""
    rows = [
        ComponentRow(
            kind=c.kind,
            name=c.name,
            exported=c.exported,
            guarded=c.has_permission,
            intent_filters=c.intent_filters,
        )
        for c in manifest.components
    ]
    return Inventory(package=manifest.package, rows=rows)


@dataclass
class TriageHit:
    package: str
    reason: str

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def is_system_package(pkg: str) -> bool:
    p = pkg.strip()
    if p in _SYSTEM_EXACT:
        return True
    return any(p.startswith(pre) for pre in _SYSTEM_PREFIXES)


def triage_package_list(
    packages: Iterable[str],
    *,
    allowlist: Iterable[str] = (),
    include_system: bool = False,
) -> list[TriageHit]:
    """Offline triage of a captured package-name list.

    ``packages`` is typically the lines of a saved ``pm list packages`` dump
    (with or without the ``package:`` prefix). Returns name-shape heuristic
    hits. Packages on ``allowlist`` are never flagged; system packages are
    skipped unless ``include_system`` is set.
    """
    allow = {a.strip() for a in allowlist}
    hits: list[TriageHit] = []
    for raw in packages:
        pkg = raw.strip()
        if pkg.startswith("package:"):
            pkg = pkg.split(":", 1)[1].strip()
        if not pkg or pkg in allow:
            continue
        if not include_system and is_system_package(pkg):
            continue
        low = pkg.lower()
        for needle in _SUSPICIOUS_SUBSTRINGS:
            if needle in low:
                hits.append(TriageHit(package=pkg, reason=f"name matches heuristic {needle!r}"))
                break
    return hits


def render_inventory(inv: Inventory) -> str:
    lines = [f"package: {inv.package or '(unknown)'}",
             f"components: {inv.to_dict()['total']} "
             f"({inv.to_dict()['exported_unguarded']} exported & unguarded)"]
    for r in inv.rows:
        flags = []
        if r.exported:
            flags.append("exported")
        if r.guarded:
            flags.append("guarded")
        if r.intent_filters:
            flags.append(f"{r.intent_filters} intent-filter(s)")
        suffix = f"  [{', '.join(flags)}]" if flags else ""
        lines.append(f"  {r.kind:9} {r.name}{suffix}")
    return "\n".join(lines)
