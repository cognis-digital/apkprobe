"""APK version diffing — supply-chain / update-time regression detection.

A defender rarely reviews an app once. They review it again on every update,
and the question that matters is: *what changed, and did it get worse?* A
silent update that newly turns on ``debuggable``, adds ``READ_SMS``, exports a
new unguarded provider, rotates to a different signing key, or embeds a fresh
API key is exactly the kind of supply-chain regression that single-version
scanning misses.

:func:`diff_manifests` and :func:`diff_reports` compare two analyses (an
"old"/baseline and a "new"/candidate) and classify every delta as a
**regression** (security got worse), an **improvement** (got better), or a
neutral change. The result has a deterministic, machine-readable shape and a
non-zero "verdict" when any regression is present, so it drops into an
update-gate CI step the same way a single scan does.

Pure stdlib, deterministic, offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .manifest import AppManifest
from .attacksurface import PERMISSION_KB, profile

REGRESSION = "regression"
IMPROVEMENT = "improvement"
NEUTRAL = "neutral"


@dataclass
class Delta:
    kind: str          # what changed, e.g. "permission.added"
    classification: str  # REGRESSION | IMPROVEMENT | NEUTRAL
    detail: str
    weight: int = 0    # severity weight for regressions (0 for neutral)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "classification": self.classification,
            "detail": self.detail,
            "weight": self.weight,
        }


@dataclass
class DiffResult:
    old_package: str
    new_package: str
    deltas: list[Delta] = field(default_factory=list)

    def regressions(self) -> list[Delta]:
        return [d for d in self.deltas if d.classification == REGRESSION]

    def improvements(self) -> list[Delta]:
        return [d for d in self.deltas if d.classification == IMPROVEMENT]

    def risk_delta(self) -> int:
        """new_score - old_score (positive = riskier)."""
        return self._risk_delta

    @property
    def verdict(self) -> str:
        if self.regressions():
            return "REGRESSED"
        if self.improvements():
            return "IMPROVED"
        return "UNCHANGED"

    def to_dict(self) -> dict:
        return {
            "old_package": self.old_package,
            "new_package": self.new_package,
            "verdict": self.verdict,
            "risk_delta": self._risk_delta,
            "regression_count": len(self.regressions()),
            "improvement_count": len(self.improvements()),
            "deltas": [d.to_dict() for d in self.deltas],
        }

    _risk_delta: int = 0


_FLAG_REGRESSIONS = {
    # attr_name: (becoming-true-is-bad?, weight, label)
    "debuggable": (True, 12, "android:debuggable"),
    "uses_cleartext_traffic": (True, 8, "android:usesCleartextTraffic"),
    "allow_backup": (True, 4, "android:allowBackup"),
}


def diff_manifests(old: AppManifest, new: AppManifest) -> DiffResult:
    """Compare two parsed manifests, classifying every delta."""
    res = DiffResult(old_package=old.package, new_package=new.package)

    # Package identity change is itself notable (repackaging / takeover).
    if old.package and new.package and old.package != new.package:
        res.deltas.append(Delta(
            "package.changed", REGRESSION,
            f"package id changed {old.package!r} -> {new.package!r}", 10))

    # --- permissions ------------------------------------------------------
    old_perms, new_perms = set(old.permissions), set(new.permissions)
    for perm in sorted(new_perms - old_perms):
        info = PERMISSION_KB.get(perm)
        w = info.weight if info else 2
        cap = f" ({info.capability})" if info else ""
        res.deltas.append(Delta(
            "permission.added", REGRESSION,
            f"newly requests {perm}{cap}", w))
    for perm in sorted(old_perms - new_perms):
        res.deltas.append(Delta(
            "permission.removed", IMPROVEMENT,
            f"no longer requests {perm}", 0))

    # --- config / hardening flags ----------------------------------------
    for attr, (bad_when_true, weight, label) in _FLAG_REGRESSIONS.items():
        ov, nv = getattr(old, attr), getattr(new, attr)
        # normalize tri-state cleartext (None -> treated as False for diffing)
        ov = bool(ov) if ov is not None else False
        nv = bool(nv) if nv is not None else False
        if ov == nv:
            continue
        if nv and bad_when_true:
            res.deltas.append(Delta(
                f"flag.{attr}", REGRESSION, f"{label} turned ON", weight))
        elif ov and bad_when_true:
            res.deltas.append(Delta(
                f"flag.{attr}", IMPROVEMENT, f"{label} turned OFF", 0))

    # network security config presence
    if old.network_security_config and not new.network_security_config:
        res.deltas.append(Delta(
            "flag.network_security_config", REGRESSION,
            "Network Security Config removed", 5))
    elif not old.network_security_config and new.network_security_config:
        res.deltas.append(Delta(
            "flag.network_security_config", IMPROVEMENT,
            "Network Security Config added", 0))

    # min sdk floor lowering re-inherits old-platform vulns
    if old.min_sdk and new.min_sdk and new.min_sdk < old.min_sdk:
        res.deltas.append(Delta(
            "sdk.min_lowered", REGRESSION,
            f"minSdkVersion lowered {old.min_sdk} -> {new.min_sdk}", 4))
    elif old.min_sdk and new.min_sdk and new.min_sdk > old.min_sdk:
        res.deltas.append(Delta(
            "sdk.min_raised", IMPROVEMENT,
            f"minSdkVersion raised {old.min_sdk} -> {new.min_sdk}", 0))

    # --- exported component surface --------------------------------------
    def comp_key(c):
        return (c.kind, c.name)

    old_exported = {comp_key(c): c for c in old.components if c.exported}
    new_exported = {comp_key(c): c for c in new.components if c.exported}
    for key in sorted(new_exported.keys() - old_exported.keys()):
        c = new_exported[key]
        guarded = c.has_permission
        cls = NEUTRAL if guarded else REGRESSION
        w = 0 if guarded else (5 if c.kind == "provider" else 3)
        res.deltas.append(Delta(
            "component.exported.added", cls,
            f"newly exported {c.kind} {c.name} "
            f"({'guarded' if guarded else 'UNGUARDED'})", w))
    for key in sorted(old_exported.keys() - new_exported.keys()):
        c = old_exported[key]
        res.deltas.append(Delta(
            "component.exported.removed", IMPROVEMENT,
            f"no longer exports {c.kind} {c.name}", 0))
    # a component that lost its permission guard
    for key in sorted(old_exported.keys() & new_exported.keys()):
        oc, nc = old_exported[key], new_exported[key]
        if oc.has_permission and not nc.has_permission:
            res.deltas.append(Delta(
                "component.guard.removed", REGRESSION,
                f"{nc.kind} {nc.name} lost its permission guard", 5))
        elif not oc.has_permission and nc.has_permission:
            res.deltas.append(Delta(
                "component.guard.added", IMPROVEMENT,
                f"{nc.kind} {nc.name} gained a permission guard", 0))

    # stable ordering: regressions first (by weight desc), then others
    order = {REGRESSION: 0, NEUTRAL: 1, IMPROVEMENT: 2}
    res.deltas.sort(key=lambda d: (order[d.classification], -d.weight, d.kind))

    res._risk_delta = profile(new).score - profile(old).score
    return res


def diff_reports(old_report, new_report) -> DiffResult:
    """Diff two full :class:`apkprobe.analyzer.Report` objects.

    Adds signing-scheme and embedded-secret deltas on top of the manifest diff,
    using each report's own manifest (re-parsed by the caller and attached as
    ``report.manifest``) when present; otherwise falls back to a finding diff.
    """
    old_m = getattr(old_report, "manifest", None)
    new_m = getattr(new_report, "manifest", None)
    if old_m is not None and new_m is not None:
        res = diff_manifests(old_m, new_m)
    else:
        res = DiffResult(old_package=old_report.package,
                         new_package=new_report.package)

    # signing scheme change (key rotation / scheme downgrade)
    old_sig = set(old_report.signature_schemes)
    new_sig = set(new_report.signature_schemes)
    if old_sig and not new_sig:
        res.deltas.append(Delta(
            "signing.removed", REGRESSION, "signature no longer detected", 8))
    elif old_sig != new_sig:
        added = sorted(new_sig - old_sig)
        removed = sorted(old_sig - new_sig)
        # losing v2+ while keeping only v1 is a downgrade
        cls = NEUTRAL
        w = 0
        if any("v2" in s or "v3" in s for s in removed):
            cls, w = REGRESSION, 6
        res.deltas.append(Delta(
            "signing.changed", cls,
            f"signing schemes changed (+{added} / -{removed})", w))

    # embedded-secret delta from findings
    def secret_evidence(report):
        return {
            f.evidence for f in report.findings
            if "secret" in f.title.lower()
        }
    old_secrets = secret_evidence(old_report)
    new_secrets = secret_evidence(new_report)
    for ev in sorted(new_secrets - old_secrets):
        res.deltas.append(Delta(
            "secret.added", REGRESSION,
            f"new embedded secret: {ev}", 9))
    for ev in sorted(old_secrets - new_secrets):
        res.deltas.append(Delta(
            "secret.removed", IMPROVEMENT,
            f"embedded secret removed: {ev}", 0))

    order = {REGRESSION: 0, NEUTRAL: 1, IMPROVEMENT: 2}
    res.deltas.sort(key=lambda d: (order[d.classification], -d.weight, d.kind))
    return res


def render_text(res: DiffResult) -> str:
    lines: list[str] = []
    lines.append(f"old: {res.old_package or '(unknown)'}")
    lines.append(f"new: {res.new_package or '(unknown)'}")
    lines.append(f"verdict: {res.verdict}  (risk delta {res._risk_delta:+d})")
    regs = res.regressions()
    imps = res.improvements()
    if regs:
        lines.append(f"regressions ({len(regs)}):")
        for d in regs:
            lines.append(f"  [-{d.weight:<2}] {d.kind}: {d.detail}")
    if imps:
        lines.append(f"improvements ({len(imps)}):")
        for d in imps:
            lines.append(f"  [ok ] {d.kind}: {d.detail}")
    neutral = [d for d in res.deltas if d.classification == NEUTRAL]
    if neutral:
        lines.append(f"other changes ({len(neutral)}):")
        for d in neutral:
            lines.append(f"  [~  ] {d.kind}: {d.detail}")
    if not res.deltas:
        lines.append("no manifest-level changes detected")
    return "\n".join(lines)
