"""MASTG-aligned static checks over a parsed manifest.

Each check returns zero or more findings using the shared schema from
``scopeward.findings`` when available, falling back to a local-compatible
Finding so apkprobe also runs standalone. Checks map to MASVS controls /
MASTG test ids so results slot into a coverage matrix.
"""

from __future__ import annotations

from .manifest import AppManifest

try:  # prefer the suite-wide schema
    from scopeward.findings import Finding, Severity
    _HAVE_SCOPEWARD = True
except Exception:  # pragma: no cover - standalone fallback
    import enum
    from dataclasses import dataclass, field

    class Severity(enum.IntEnum):
        INFO = 0
        LOW = 1
        MEDIUM = 2
        HIGH = 3
        CRITICAL = 4

        @classmethod
        def parse(cls, v):
            return v if isinstance(v, cls) else cls[str(v).upper()]

    @dataclass
    class Finding:  # minimal compatible shape
        title: str
        severity: "Severity"
        target: str
        description: str = ""
        module: str = "apkprobe"
        masvs: str = ""
        mastg_test: str = ""
        evidence: str = ""
        metadata: dict = field(default_factory=dict)

        def to_dict(self):
            d = dict(self.__dict__)
            d["severity"] = Severity.parse(self.severity).name
            return d

    _HAVE_SCOPEWARD = False


# Permissions worth surfacing (subset of Android's "dangerous"/sensitive set)
SENSITIVE_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CAMERA",
    "android.permission.REQUEST_INSTALL_PACKAGES",
}


def analyze_manifest(m: AppManifest) -> list:
    target = f"android:{m.package}" if m.package else "android:unknown"
    findings: list = []

    def add(title, sev, masvs, mastg, evidence, desc=""):
        findings.append(Finding(
            title=title, severity=Severity.parse(sev), target=target,
            module="apkprobe", masvs=masvs, mastg_test=mastg,
            evidence=evidence, description=desc,
        ))

    if m.debuggable:
        add("Application is debuggable", "HIGH", "MASVS-RESILIENCE-2", "MASTG-TEST-0026",
            "android:debuggable=\"true\"",
            "A debuggable build lets anyone attach a debugger and inspect/modify the running app.")

    if m.allow_backup:
        add("ADB backup allowed", "MEDIUM", "MASVS-STORAGE-2", "MASTG-TEST-0009",
            "android:allowBackup=\"true\"",
            "App data can be extracted via 'adb backup' on a debuggable-or-rooted device.")

    if m.uses_cleartext_traffic is True:
        add("Cleartext (HTTP) traffic permitted", "HIGH", "MASVS-NETWORK-1", "MASTG-TEST-0019",
            "android:usesCleartextTraffic=\"true\"",
            "App allows unencrypted network traffic, exposing data to interception.")

    if m.target_sdk and m.target_sdk >= 24 and not m.network_security_config \
            and m.uses_cleartext_traffic is not False:
        add("No Network Security Config", "LOW", "MASVS-NETWORK-2", "MASTG-TEST-0020",
            f"targetSdk={m.target_sdk}, no android:networkSecurityConfig",
            "No NSC means default trust + no pinning policy; consider an explicit config.")

    for c in m.components:
        if c.exported and not c.has_permission:
            sev = "MEDIUM" if c.intent_filters else "LOW"
            add(f"Exported {c.kind} without permission: {c.name}", sev,
                "MASVS-PLATFORM-1", "MASTG-TEST-0024",
                f"{c.kind} {c.name} exported=true, permission=none, intent-filters={c.intent_filters}",
                "Exported component reachable by other apps with no permission guard.")

    for perm in sorted(set(m.permissions) & SENSITIVE_PERMISSIONS):
        add(f"Sensitive permission requested: {perm}", "INFO",
            "MASVS-PLATFORM-1", "MASTG-TEST-0024", perm,
            "Verify this permission is actually required and justified.")

    if m.min_sdk and m.min_sdk < 24:
        add(f"Low minSdkVersion ({m.min_sdk})", "LOW", "MASVS-RESILIENCE-1", "",
            f"minSdkVersion={m.min_sdk}",
            "Supporting old Android versions inherits their unpatched platform vulnerabilities.")

    return findings
