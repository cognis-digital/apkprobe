"""Top-level analysis orchestration with optional scopeward gating.

If an :class:`scopeward.authz.Authorizer` is supplied, the target package must
be authorized for the ``apkprobe`` module before any analysis runs — otherwise
:class:`scopeward.authz.ScopeViolation` propagates and nothing is read. Without
an authorizer, apkprobe runs standalone (CI, your own apps, lab) but prints a
reminder that engagement use should be scoped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .apk import Apk
from .rules import analyze_manifest, Finding, Severity
from .secrets import scan_text


@dataclass
class Report:
    package: str
    signature_schemes: list[str]
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "signature_schemes": self.signature_schemes,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }

    def max_severity(self) -> int:
        return max((int(Severity.parse(f.severity)) for f in self.findings), default=0)


def analyze_apk(path: str, authorizer: Optional[object] = None) -> Report:
    with Apk(path) as apk:
        manifest = apk.manifest()
        target_pkg = manifest.package

        if authorizer is not None:
            # Import here so apkprobe has no hard dependency on scopeward.
            from scopeward.scope import Target
            authorizer.authorize("apkprobe", target=Target("android", target_pkg))

        findings = list(analyze_manifest(manifest))

        target = f"android:{target_pkg}" if target_pkg else "android:unknown"
        for name, text in apk.text_entries():
            for hit in scan_text(text, name):
                findings.append(Finding(
                    title=f"Possible embedded secret: {hit.kind}",
                    severity=Severity.parse("HIGH"),
                    target=target, module="apkprobe",
                    masvs="MASVS-STORAGE-1", mastg_test="MASTG-TEST-0011",
                    evidence=f"{hit.where}: {hit.sample}",
                    description="Hard-coded credential material in a shipped resource.",
                ))

        report = Report(
            package=target_pkg,
            signature_schemes=apk.signature_schemes(),
            findings=findings,
        )

        if not report.signature_schemes:
            findings.append(Finding(
                title="APK is unsigned or signature not detected",
                severity=Severity.parse("MEDIUM"),
                target=target, module="apkprobe",
                masvs="MASVS-RESILIENCE-1", mastg_test="",
                evidence="no META-INF signature and no APK Signing Block",
            ))
        return report
