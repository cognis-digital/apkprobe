"""Attack-surface profiling and defensive risk scoring.

apkprobe's rule engine (``rules.py``) answers *"which individual MASTG checks
fail?"*. This module answers the question a defender actually asks first:
*"how exposed is this app overall, and through what?"*

It produces an :class:`AttackSurface` that:

* maps each requested Android permission to the **capability** it grants and a
  documented **abuse vector** (data exfiltration, surveillance, billing fraud,
  device admin, etc.) — so a triager sees *intent*, not just a permission name;
* enumerates the **IPC attack surface**: every exported component reachable by
  other apps on the device, split by whether a permission guards it;
* rolls everything into a single bounded **risk score (0–100)** with a letter
  grade and a transparent, reproducible breakdown of every point added.

Everything here is pure-stdlib, deterministic, and offline. The capability
table is hand-curated from the Android platform permission reference and the
OWASP MASTG — it contains **no fabricated CVEs or intel**, only documented
platform behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .manifest import AppManifest

# ---------------------------------------------------------------------------
# Permission -> capability / abuse-vector knowledge base.
#
# Sourced from the Android platform permission reference and OWASP MASTG. Each
# entry is documented platform behaviour, not speculative intel. ``weight`` is
# the contribution to the risk score when the permission is requested.
# ---------------------------------------------------------------------------

# vector tags (defensive taxonomy)
V_LOCATION = "surveillance:location"
V_AUDIO = "surveillance:audio"
V_CAMERA = "surveillance:camera"
V_MESSAGING = "exfiltration:messaging"
V_CONTACTS = "exfiltration:pii"
V_STORAGE = "exfiltration:storage"
V_TELEPHONY = "fraud:telephony"
V_BILLING = "fraud:billing"
V_INSTALL = "persistence:install"
V_ADMIN = "control:device-admin"
V_ACCESSIBILITY = "control:accessibility"
V_OVERLAY = "deception:overlay"
V_IDENTITY = "exfiltration:identity"
V_NETWORK = "network"
V_BACKGROUND = "persistence:background"


@dataclass(frozen=True)
class PermInfo:
    capability: str
    vector: str
    weight: int
    note: str = ""


# A focused, high-signal subset. Keys are the bare Android permission constants.
PERMISSION_KB: dict[str, PermInfo] = {
    "android.permission.ACCESS_FINE_LOCATION": PermInfo(
        "Precise GPS location", V_LOCATION, 8,
        "Continuous fine location enables physical tracking of the user."),
    "android.permission.ACCESS_COARSE_LOCATION": PermInfo(
        "Approximate location", V_LOCATION, 5,
        "Network/cell location; coarse but still trackable."),
    "android.permission.ACCESS_BACKGROUND_LOCATION": PermInfo(
        "Location while backgrounded", V_LOCATION, 10,
        "Tracks the user even when the app is not in the foreground."),
    "android.permission.RECORD_AUDIO": PermInfo(
        "Microphone capture", V_AUDIO, 9,
        "Can record ambient audio; classic spyware capability."),
    "android.permission.CAMERA": PermInfo(
        "Camera capture", V_CAMERA, 8,
        "Still/video capture; surveillance and document-theft risk."),
    "android.permission.READ_SMS": PermInfo(
        "Read SMS/MMS", V_MESSAGING, 9,
        "Reads 2FA codes and private messages; high exfiltration value."),
    "android.permission.SEND_SMS": PermInfo(
        "Send SMS", V_BILLING, 9,
        "Premium-SMS billing fraud and silent C2 exfiltration channel."),
    "android.permission.RECEIVE_SMS": PermInfo(
        "Intercept incoming SMS", V_MESSAGING, 8,
        "Intercepts OTP/2FA codes before the user sees them."),
    "android.permission.READ_CONTACTS": PermInfo(
        "Read contacts", V_CONTACTS, 6,
        "Address-book harvesting for spam/social-engineering pivots."),
    "android.permission.WRITE_CONTACTS": PermInfo(
        "Modify contacts", V_CONTACTS, 4,
        "Can inject/alter contacts (phishing prep)."),
    "android.permission.READ_CALL_LOG": PermInfo(
        "Read call history", V_CONTACTS, 6,
        "Call-graph harvesting; sensitive relationship metadata."),
    "android.permission.READ_PHONE_STATE": PermInfo(
        "Phone/SIM identifiers", V_IDENTITY, 5,
        "Device/SIM identifiers used for stable fingerprinting."),
    "android.permission.READ_PHONE_NUMBERS": PermInfo(
        "Device phone number", V_IDENTITY, 4,
        "Reads the device MSISDN; identity correlation."),
    "android.permission.CALL_PHONE": PermInfo(
        "Place calls", V_TELEPHONY, 6,
        "Can initiate calls (premium-number fraud)."),
    "android.permission.PROCESS_OUTGOING_CALLS": PermInfo(
        "Intercept outgoing calls", V_TELEPHONY, 6,
        "Observe/redirect dialed numbers."),
    "android.permission.READ_EXTERNAL_STORAGE": PermInfo(
        "Read shared storage", V_STORAGE, 4,
        "Reads user media/files outside the sandbox."),
    "android.permission.WRITE_EXTERNAL_STORAGE": PermInfo(
        "Write shared storage", V_STORAGE, 4,
        "Can drop payloads/exfil staging into shared storage."),
    "android.permission.MANAGE_EXTERNAL_STORAGE": PermInfo(
        "All-files access", V_STORAGE, 9,
        "Scoped-storage bypass; broad filesystem read/write."),
    "android.permission.REQUEST_INSTALL_PACKAGES": PermInfo(
        "Install other APKs", V_INSTALL, 9,
        "Side-loading vector; dropper / second-stage installer."),
    "android.permission.BIND_DEVICE_ADMIN": PermInfo(
        "Device administration", V_ADMIN, 10,
        "Lock/wipe/policy control; ransomware & anti-uninstall."),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": PermInfo(
        "Accessibility service", V_ACCESSIBILITY, 10,
        "Screen-reading + input synthesis; banking-trojan staple."),
    "android.permission.SYSTEM_ALERT_WINDOW": PermInfo(
        "Draw over other apps", V_OVERLAY, 8,
        "Tapjacking / credential-overlay phishing."),
    "android.permission.GET_ACCOUNTS": PermInfo(
        "Enumerate accounts", V_IDENTITY, 3,
        "Lists on-device accounts (identity correlation)."),
    "android.permission.FOREGROUND_SERVICE": PermInfo(
        "Persistent foreground service", V_BACKGROUND, 2,
        "Long-running execution; persistence enabler."),
    "android.permission.RECEIVE_BOOT_COMPLETED": PermInfo(
        "Start on boot", V_BACKGROUND, 3,
        "Auto-launch on boot; persistence."),
    "android.permission.QUERY_ALL_PACKAGES": PermInfo(
        "Enumerate installed apps", V_IDENTITY, 4,
        "Full app inventory; targeting/fingerprinting + sensitive."),
    "android.permission.INTERNET": PermInfo(
        "Network access", V_NETWORK, 1,
        "Required for any remote exfiltration channel."),
}


@dataclass
class CapabilityHit:
    permission: str
    capability: str
    vector: str
    weight: int
    note: str


@dataclass
class ExposedComponent:
    kind: str
    name: str
    guarded: bool
    intent_filters: int


@dataclass
class AttackSurface:
    package: str
    capabilities: list[CapabilityHit] = field(default_factory=list)
    unknown_permissions: list[str] = field(default_factory=list)
    exposed_components: list[ExposedComponent] = field(default_factory=list)
    flags: dict = field(default_factory=dict)
    score: int = 0
    grade: str = "A"
    score_breakdown: list[tuple[str, int]] = field(default_factory=list)

    # -- derived views -----------------------------------------------------
    def vectors(self) -> dict[str, list[str]]:
        """Map abuse-vector -> capabilities present, for quick triage."""
        out: dict[str, list[str]] = {}
        for c in self.capabilities:
            out.setdefault(c.vector, []).append(c.capability)
        return out

    def unguarded_components(self) -> list[ExposedComponent]:
        return [c for c in self.exposed_components if not c.guarded]

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "score": self.score,
            "grade": self.grade,
            "score_breakdown": [
                {"reason": r, "points": p} for r, p in self.score_breakdown
            ],
            "flags": self.flags,
            "vectors": self.vectors(),
            "capabilities": [
                {
                    "permission": c.permission,
                    "capability": c.capability,
                    "vector": c.vector,
                    "weight": c.weight,
                    "note": c.note,
                }
                for c in self.capabilities
            ],
            "unknown_permissions": self.unknown_permissions,
            "exposed_components": [
                {
                    "kind": e.kind,
                    "name": e.name,
                    "guarded": e.guarded,
                    "intent_filters": e.intent_filters,
                }
                for e in self.exposed_components
            ],
        }


# ---------------------------------------------------------------------------
# Scoring. Bounded 0..100, every point attributed in ``score_breakdown``.
# ---------------------------------------------------------------------------

_GRADE_BANDS = [
    (80, "F"),
    (60, "E"),
    (45, "D"),
    (30, "C"),
    (15, "B"),
    (0, "A"),
]


def _grade(score: int) -> str:
    for threshold, letter in _GRADE_BANDS:
        if score >= threshold:
            return letter
    return "A"


def profile(m: AppManifest) -> AttackSurface:
    """Build an :class:`AttackSurface` from a parsed manifest."""
    surf = AttackSurface(package=m.package)
    breakdown: list[tuple[str, int]] = []

    # 1. Permission capabilities -------------------------------------------
    seen: set[str] = set()
    for perm in m.permissions:
        if perm in seen:
            continue
        seen.add(perm)
        info = PERMISSION_KB.get(perm)
        if info is None:
            # Unknown / non-catalogued permission: still note, small weight if
            # it is clearly a signature/system-style permission name.
            surf.unknown_permissions.append(perm)
            continue
        surf.capabilities.append(CapabilityHit(
            permission=perm, capability=info.capability, vector=info.vector,
            weight=info.weight, note=info.note,
        ))

    # Cap permission contribution so a kitchen-sink app can't blow past the
    # config-flag signals. Sort high-weight first for stable, readable output.
    surf.capabilities.sort(key=lambda c: (-c.weight, c.permission))
    perm_points = min(50, sum(c.weight for c in surf.capabilities))
    if perm_points:
        breakdown.append(("requested-capabilities", perm_points))

    # Vector diversity bonus: an app touching many distinct abuse vectors is
    # more concerning than one with several perms in a single vector.
    distinct_vectors = {c.vector for c in surf.capabilities} - {V_NETWORK}
    if len(distinct_vectors) >= 4:
        breakdown.append(("multi-vector-capability", 6))
    elif len(distinct_vectors) == 3:
        breakdown.append(("multi-vector-capability", 3))

    # 2. IPC / exported-component surface ----------------------------------
    for c in m.components:
        if c.exported:
            surf.exposed_components.append(ExposedComponent(
                kind=c.kind, name=c.name, guarded=c.has_permission,
                intent_filters=c.intent_filters,
            ))
    unguarded = [e for e in surf.exposed_components if not e.guarded]
    if unguarded:
        # 3 points each, capped, providers weigh extra (data leakage).
        provider_extra = sum(2 for e in unguarded if e.kind == "provider")
        ipc_points = min(18, len(unguarded) * 3 + provider_extra)
        breakdown.append(("unguarded-exported-components", ipc_points))

    # 3. Hardening / config flags ------------------------------------------
    flags = {
        "debuggable": m.debuggable,
        "allow_backup": m.allow_backup,
        "uses_cleartext_traffic": m.uses_cleartext_traffic is True,
        "has_network_security_config": bool(m.network_security_config),
        "min_sdk": m.min_sdk,
        "target_sdk": m.target_sdk,
    }
    surf.flags = flags
    if m.debuggable:
        breakdown.append(("debuggable", 12))
    if m.uses_cleartext_traffic is True:
        breakdown.append(("cleartext-traffic", 8))
    if m.allow_backup:
        breakdown.append(("adb-backup-allowed", 4))
    if m.min_sdk and m.min_sdk < 24:
        breakdown.append(("low-min-sdk", 4))

    score = min(100, sum(p for _, p in breakdown))
    surf.score = score
    surf.score_breakdown = breakdown
    surf.grade = _grade(score)
    return surf


def render_text(surf: AttackSurface) -> str:
    """Human-readable attack-surface profile."""
    lines: list[str] = []
    lines.append(f"package: {surf.package or '(unknown)'}")
    lines.append(f"risk score: {surf.score}/100  (grade {surf.grade})")
    if surf.score_breakdown:
        lines.append("score breakdown:")
        for reason, pts in surf.score_breakdown:
            lines.append(f"  +{pts:<3} {reason}")
    vectors = surf.vectors()
    if vectors:
        lines.append("abuse vectors:")
        for vector in sorted(vectors):
            caps = ", ".join(sorted(set(vectors[vector])))
            lines.append(f"  {vector}: {caps}")
    if surf.capabilities:
        lines.append("capabilities (by weight):")
        for c in surf.capabilities:
            lines.append(f"  [{c.weight:2}] {c.capability} — {c.note}")
    if surf.unknown_permissions:
        lines.append("uncatalogued permissions:")
        for p in sorted(surf.unknown_permissions):
            lines.append(f"  {p}")
    exposed = surf.exposed_components
    if exposed:
        lines.append("exported IPC surface:")
        for e in exposed:
            guard = "guarded" if e.guarded else "UNGUARDED"
            lines.append(
                f"  {e.kind} {e.name} [{guard}] intent-filters={e.intent_filters}")
    return "\n".join(lines)
