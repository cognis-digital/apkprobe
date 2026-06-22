"""Normalized manifest JSON — the contract shared with the language ports.

The Go/Rust/TypeScript ports in ``ports/`` re-implement apkprobe's core rule
engine, but they do not contain the binary-AXML decoder. They consume an
already-decoded manifest as JSON. This module produces exactly that shape from a
parsed :class:`AppManifest`, so the Python reference and every port speak the
same wire format.

Pure stdlib, offline.
"""

from __future__ import annotations

import json

from .manifest import AppManifest


def normalize_manifest(m: AppManifest) -> dict:
    """Serialize an AppManifest to the normalized dict the ports consume."""
    return {
        "package": m.package,
        "min_sdk": m.min_sdk,
        "target_sdk": m.target_sdk,
        "debuggable": m.debuggable,
        "allow_backup": m.allow_backup,
        # may be true / false / null (unset)
        "uses_cleartext_traffic": m.uses_cleartext_traffic,
        "network_security_config": m.network_security_config,
        "permissions": list(m.permissions),
        "components": [
            {
                "kind": c.kind,
                "name": c.name,
                "exported": c.exported,
                "has_permission": c.has_permission,
                "intent_filters": c.intent_filters,
            }
            for c in m.components
        ],
    }


def normalize_manifest_json(m: AppManifest, indent: int | None = 2) -> str:
    return json.dumps(normalize_manifest(m), indent=indent)
