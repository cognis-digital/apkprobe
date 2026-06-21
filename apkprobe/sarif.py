"""SARIF 2.1.0 export for apkprobe reports.

SARIF (Static Analysis Results Interchange Format) is what GitHub code-scanning,
Azure DevOps, and most security dashboards ingest. Emitting it lets an APK scan
drop straight into a CI security gate:

    apkprobe scan app.apk --format sarif > apkprobe.sarif
    # → upload via github/codeql-action/upload-sarif

Each MASVS/MASTG check becomes a SARIF *rule*; each finding a *result* with a
mapped level, the MASVS/MASTG ids as properties, a logical location for the
package, and a stable partial fingerprint so the same issue dedupes across runs.
Standard library only.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .rules import Severity

# SARIF result levels — apkprobe severities collapse to SARIF's three.
_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}
_RANK = {"CRITICAL": 95.0, "HIGH": 80.0, "MEDIUM": 50.0, "LOW": 25.0, "INFO": 5.0}


def _rule_id(f) -> str:
    """Stable rule id: prefer the MASTG test, then MASVS, then a title slug."""
    if f.mastg_test:
        return f.mastg_test
    if f.masvs:
        return f.masvs
    slug = "".join(c if c.isalnum() else "-" for c in f.title.lower()).strip("-")
    return f"apkprobe-{slug[:40]}"


def _fingerprint(f) -> str:
    basis = f"{_rule_id(f)}|{f.target}|{f.evidence}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def to_sarif(report) -> dict[str, Any]:
    """Build a SARIF 2.1.0 document (dict) from an apkprobe Report."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in report.findings:
        sev = Severity.parse(f.severity).name
        rid = _rule_id(f)
        if rid not in rules:
            help_uri = ""
            if f.mastg_test:
                help_uri = f"https://mas.owasp.org/MASTG/tests/{f.mastg_test}/"
            rules[rid] = {
                "id": rid,
                "name": (f.masvs or rid).replace("-", ""),
                "shortDescription": {"text": f.title},
                "properties": {
                    "masvs": f.masvs,
                    "mastg": f.mastg_test,
                    "tags": [t for t in ("mobile", "android", f.masvs) if t],
                },
                **({"helpUri": help_uri} if help_uri else {}),
            }
        results.append({
            "ruleId": rid,
            "level": _LEVEL.get(sev, "warning"),
            "rank": _RANK.get(sev, 50.0),
            "message": {"text": f"{f.title}. {f.evidence}".strip()},
            "locations": [{
                "logicalLocations": [{
                    "name": f.target or "android:unknown",
                    "kind": "namespace",
                }],
            }],
            "partialFingerprints": {"apkprobe/v1": _fingerprint(f)},
            "properties": {
                "severity": sev,
                "masvs": f.masvs,
                "mastg": f.mastg_test,
                "evidence": f.evidence,
            },
        })

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "apkprobe",
                    "informationUri": "https://github.com/cognis-digital/apkprobe",
                    "rules": list(rules.values()),
                },
            },
            "properties": {
                "package": report.package,
                "signature_schemes": report.signature_schemes,
            },
            "results": results,
        }],
    }


def to_sarif_json(report, indent: int = 2) -> str:
    return json.dumps(to_sarif(report), indent=indent)
