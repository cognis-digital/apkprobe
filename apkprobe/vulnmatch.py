"""Match an APK's component evidence against the bundled OSV vulnerability DB.

This wires :mod:`apkprobe.components` (real evidence harvested from the APK) to
:mod:`apkprobe.vulndb_local` (the bundled ~262k-record OSV corpus) — fully
offline, no network, no fabricated data.

What it correlates:
  * **Advisory references** (CVE/GHSA ids the app names verbatim, e.g. in an
    OSS-credits/SBOM file) -> the matching DB record(s).
  * **Package coordinates** (Maven ``group:artifact``, npm names, native lib
    names) -> DB records whose ``packages`` list contains that name.

Honest scope: the bundled corpus is *name/advisory-keyed* (compact OSV), so a
package match means "this component is named in N known advisories", not a
version-resolved exploitability verdict. Matches are ranked and labelled with
confidence (``exact-advisory`` > ``coordinate`` > ``artifact-name`` >
``native-name``) and every hit is attributed to the APK entry it came from. To
get version-precise resolution, refresh the full OSV range data with
``apkprobe.datafeeds`` (``osv`` / ``nvd-cve`` feeds) on a connected box and run
in an edge cache — see the README "Edge / air-gap" note.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .components import ComponentEvidence, extract_components, split_evidence
from .vulndb_local import VulnDB

# CVSS v3.x base-score component weights (enough to derive a qualitative band).
_CVSS3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_CVSS3_AC = {"L": 0.77, "H": 0.44}
_CVSS3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_CVSS3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}    # scope changed
_CVSS3_UI = {"N": 0.85, "R": 0.62}
_CVSS3_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    # CVSS "Roundup": ceiling to one decimal place.
    import math
    return math.ceil(x * 10) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    """Compute the CVSS v3.x base score from a vector string. None if unparseable."""
    parts = dict(
        kv.split(":", 1) for kv in vector.split("/") if ":" in kv
    )
    try:
        av = _CVSS3_AV[parts["AV"]]
        ac = _CVSS3_AC[parts["AC"]]
        ui = _CVSS3_UI[parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr = (_CVSS3_PR_C if scope_changed else _CVSS3_PR_U)[parts["PR"]]
        c = _CVSS3_CIA[parts["C"]]
        i = _CVSS3_CIA[parts["I"]]
        a = _CVSS3_CIA[parts["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)
    return _roundup(base)


def cvss_label(severity: str) -> str:
    """Map a CVSS vector (or a bare label) to a qualitative band.

    Returns one of CRITICAL/HIGH/MEDIUM/LOW/"" — "" when unknown.
    """
    if not severity:
        return ""
    s = severity.strip().upper()
    if s in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"):
        return "MEDIUM" if s == "MODERATE" else s
    if s.startswith("CVSS:3"):
        score = cvss3_base_score(severity)
        if score is None:
            return ""
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return ""
    # CVSS:4.0 vectors: approximate from the impact triad (no full v4 calc).
    if s.startswith("CVSS:4"):
        parts = dict(kv.split(":", 1) for kv in s.split("/") if ":" in kv)
        triad = [parts.get(k, "N") for k in ("VC", "VI", "VA")]
        highs = sum(1 for v in triad if v == "H")
        if highs >= 2 and parts.get("AV") == "N" and parts.get("AC") == "L":
            return "HIGH"
        if highs >= 1:
            return "MEDIUM"
        return "LOW"
    return ""

# Confidence ordering for ranking match rows (higher = stronger).
_CONFIDENCE = {
    "exact-advisory": 4,
    "coordinate": 3,
    "artifact-name": 2,
    "native-name": 1,
}


@dataclass
class VulnHit:
    component: str          # what in the APK matched
    component_kind: str     # cve/ghsa/maven/npm/native
    where: str              # APK entry the component came from
    vuln_id: str            # OSV/GHSA id of the matched advisory
    aliases: list[str]      # incl. CVE id(s)
    ecosystem: str
    severity: str
    summary: str
    confidence: str         # see _CONFIDENCE
    matched_package: str    # the DB package name that matched (if any)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["cve"] = self.cve
        d["severity_label"] = self.severity_label
        return d

    @property
    def cve(self) -> str:
        for a in self.aliases:
            if a.upper().startswith("CVE-"):
                return a.upper()
        return self.vuln_id

    @property
    def severity_label(self) -> str:
        """Qualitative band (CRITICAL/HIGH/MEDIUM/LOW/"") from the CVSS vector."""
        return cvss_label(self.severity)


@dataclass
class VulnReport:
    package: str = ""                       # the analyzed app package, if known
    evidence: list[ComponentEvidence] = field(default_factory=list)
    hits: list[VulnHit] = field(default_factory=list)
    db_count: int = 0

    @property
    def cve_ids(self) -> list[str]:
        out: list[str] = []
        for h in self.hits:
            c = h.cve
            if c not in out:
                out.append(c)
        return out

    def max_severity_label(self) -> str:
        order = ["", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        best = ""
        for h in self.hits:
            lab = h.severity_label
            if lab in order and order.index(lab) > order.index(best):
                best = lab
        return best

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "db_count": self.db_count,
            "evidence_count": len(self.evidence),
            "hit_count": len(self.hits),
            "distinct_advisories": len({h.vuln_id for h in self.hits}),
            "cve_ids": self.cve_ids,
            "evidence": [e.to_dict() for e in self.evidence],
            "hits": [h.to_dict() for h in self.hits],
        }


def _record_to_hit(ev: ComponentEvidence, rec: dict, confidence: str,
                   matched_package: str) -> VulnHit:
    return VulnHit(
        component=ev.name + (f"@{ev.version}" if ev.version else ""),
        component_kind=ev.kind,
        where=ev.where,
        vuln_id=rec.get("id", ""),
        aliases=list(rec.get("aliases") or []),
        ecosystem=rec.get("ecosystem", ""),
        severity=rec.get("severity", "") or "",
        summary=rec.get("summary", "") or "",
        confidence=confidence,
        matched_package=matched_package,
    )


def _maven_artifact(name: str) -> str:
    """group:artifact -> artifact (bare). Returns '' if not a coordinate."""
    if ":" in name:
        return name.split(":")[-1]
    return ""


def correlate(evidence: Iterable[ComponentEvidence], db: Optional[VulnDB] = None,
              *, max_hits_per_component: int = 25) -> list[VulnHit]:
    """Correlate harvested evidence against the DB. Pure over (evidence, db)."""
    db = db or VulnDB()
    evidence = list(evidence)
    advisories, packages = split_evidence(evidence)
    hits: list[VulnHit] = []
    seen: set[tuple] = set()

    def emit(ev, rec, conf, matched_pkg):
        key = (ev.name, ev.where, rec.get("id"))
        if key in seen:
            return
        seen.add(key)
        hits.append(_record_to_hit(ev, rec, conf, matched_pkg))

    # 1) advisory ids the app names verbatim -> strongest signal
    for ev in evidence:
        if ev.kind not in ("cve", "ghsa"):
            continue
        for rec in db.by_cve(ev.name):
            emit(ev, rec, "exact-advisory", "")

    # 2) package coordinates / names
    for ev in packages:
        per = 0
        # exact coordinate match (group:artifact or npm name)
        for rec in db.by_package(ev.name):
            emit(ev, rec, "coordinate", ev.name)
            per += 1
            if per >= max_hits_per_component:
                break
        # fall back to the bare Maven artifact (group:artifact -> artifact)
        artifact = _maven_artifact(ev.name)
        if artifact and per < max_hits_per_component:
            for rec in db.by_package(artifact):
                conf = "artifact-name"
                emit(ev, rec, conf, artifact)
                per += 1
                if per >= max_hits_per_component:
                    break
        # native libs are a weak name-only signal
        if ev.kind == "native" and per < max_hits_per_component:
            for rec in db.by_package(ev.name):
                emit(ev, rec, "native-name", ev.name)
                per += 1
                if per >= max_hits_per_component:
                    break

    _sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0}
    hits.sort(key=lambda h: (
        -_CONFIDENCE.get(h.confidence, 0),
        -_sev_rank.get(h.severity_label, 0),
        h.vuln_id,
    ))
    return hits


def enrich_apk(path: str, db: Optional[VulnDB] = None) -> VulnReport:
    """Harvest component evidence from an APK and correlate it with the DB."""
    db = db or VulnDB()
    evidence = extract_components(path)
    hits = correlate(evidence, db)
    pkg = ""
    try:  # best-effort: tag the report with the app package
        from .apk import Apk
        with Apk(path) as apk:
            pkg = apk.manifest().package
    except Exception:  # pragma: no cover - non-APK ZIP fixture
        pkg = ""
    return VulnReport(package=pkg, evidence=evidence, hits=hits, db_count=db.count())


def render_text(report: VulnReport) -> str:
    lines = [
        f"package: {report.package or '(unknown)'}",
        f"vuln DB: {report.db_count} records (bundled OSV, offline)",
        f"evidence: {len(report.evidence)} component(s) harvested from the APK",
        f"matches:  {len(report.hits)} hit(s) across "
        f"{len({h.vuln_id for h in report.hits})} distinct advisor(ies)",
    ]
    if report.hits:
        worst = report.max_severity_label() or "n/a"
        lines.append(f"worst severity: {worst}")
    for h in report.hits:
        cve = h.cve
        sev = h.severity_label
        lines.append(
            f"  [{h.confidence:14}] {h.component}  ->  {cve}"
            + (f" ({sev})" if sev else "")
        )
        if h.summary:
            lines.append(f"                   {h.summary[:96]}")
        lines.append(f"                   via {h.where}")
    if not report.hits:
        lines.append("  (no components matched the bundled advisory corpus)")
    return "\n".join(lines)
