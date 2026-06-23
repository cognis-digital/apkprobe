"""Extract software-component evidence from an APK (offline, no network).

The bundled vulnerability DB (:mod:`apkprobe.vulndb_local`) is keyed by package
name (Maven/npm/PyPI/Go/…) and CVE/GHSA id. To match an APK's findings against
it we first need *real* component evidence out of the APK itself — no fabricated
intel, no fingerprint guessing. This module harvests, from the ZIP container:

* **CVE / GHSA ids** referenced verbatim in any text resource (changelogs,
  OSS-licence/credits files, SBOMs, ``third_party_licenses`` blobs). These are
  the strongest signal — the app itself names the advisory.
* **Maven coordinates** (``group:artifact:version``) and bare artifact ids that
  appear in text resources / dependency listings.
* **Bundled JavaScript libraries** — Cordova/React-Native/Capacitor apps ship
  ``node_modules``-style assets; ``foo-1.2.3.js`` / ``foo.min.js`` and
  ``package.json`` ``name``/``version`` pairs are extracted as npm coordinates.
* **Native shared objects** — ``lib/<abi>/lib<name>.so`` gives an artifact name
  (``openssl``, ``sqlite``, ``crypto``…) usable for a name match.

Every item carries the entry it came from, so the enrichment report is fully
attributed and auditable. This reads only bytes already on disk.
"""

from __future__ import annotations

import json
import posixpath
import re
import zipfile
from dataclasses import dataclass, field
from typing import Iterable, Iterator

# CVE-2021-44228 / GHSA-jfh8-c2jp-5v3q style identifiers.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_GHSA_RE = re.compile(r"\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b", re.IGNORECASE)
# group:artifact:version (Gradle/Maven). version is optional in the capture.
_MAVEN_RE = re.compile(
    r"\b([a-z0-9_.\-]+(?:\.[a-z0-9_\-]+)+):([a-z0-9_.\-]+)(?::([0-9][0-9A-Za-z.\-+]*))?\b"
)
# foo-1.2.3.js  /  foo-1.2.3.min.js  (the trailing ``.min`` is consumed, not
# folded into the version)
_JS_VERSIONED_RE = re.compile(
    r"(?:^|/)([a-z0-9][a-z0-9._\-]+?)-(\d+\.\d+(?:\.\d+)?(?:[\-+][0-9A-Za-z.]+)?)(?:\.min)?\.js$",
    re.IGNORECASE,
)
_TEXT_SUFFIXES = (
    ".txt", ".json", ".xml", ".properties", ".md", ".html", ".js", ".css",
    ".cfg", ".gradle", ".pro", ".version", ".sbom", ".csv", ".yaml", ".yml",
)
# Native libs we will not bother name-matching (too generic / always present).
_NATIVE_SKIP = {"c++_shared", "jsc", "fbjni"}


@dataclass(frozen=True)
class ComponentEvidence:
    """One observed component (or advisory ref) and where it was seen."""
    kind: str            # "cve" | "ghsa" | "maven" | "npm" | "native"
    name: str            # package/coordinate or advisory id
    version: str = ""
    where: str = ""      # zip entry it came from
    ecosystem: str = ""  # OSV ecosystem hint (Maven/npm/…), best-effort

    def to_dict(self) -> dict:
        return {
            "kind": self.kind, "name": self.name, "version": self.version,
            "where": self.where, "ecosystem": self.ecosystem,
        }


def _scan_text(name: str, text: str) -> Iterator[ComponentEvidence]:
    for m in _CVE_RE.finditer(text):
        yield ComponentEvidence("cve", m.group(0).upper(), where=name)
    for m in _GHSA_RE.finditer(text):
        yield ComponentEvidence("ghsa", m.group(0).upper(), where=name)
    for m in _MAVEN_RE.finditer(text):
        group, artifact, version = m.group(1), m.group(2), m.group(3) or ""
        # Skip XML/URL-ish false positives like "android:name" or domains.
        if group.startswith(("android", "http", "https", "www")):
            continue
        if " " in artifact:
            continue
        coord = f"{group}:{artifact}"
        yield ComponentEvidence("maven", coord, version=version,
                                where=name, ecosystem="Maven")


def _scan_js_entry(name: str) -> Iterator[ComponentEvidence]:
    m = _JS_VERSIONED_RE.search(name)
    if m:
        lib, version = m.group(1), m.group(2)
        # strip a leading path; keep just the library token
        lib = posixpath.basename(lib)
        yield ComponentEvidence("npm", lib.lower(), version=version,
                                where=name, ecosystem="npm")


def _scan_package_json(name: str, text: str) -> Iterator[ComponentEvidence]:
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return
    if not isinstance(obj, dict):
        return
    pname, pver = obj.get("name"), obj.get("version")
    if isinstance(pname, str) and pname:
        yield ComponentEvidence("npm", pname.lower(),
                                version=str(pver or ""), where=name,
                                ecosystem="npm")
    deps = {}
    for key in ("dependencies", "devDependencies"):
        d = obj.get(key)
        if isinstance(d, dict):
            deps.update(d)
    for dep, ver in deps.items():
        if isinstance(dep, str) and dep:
            yield ComponentEvidence("npm", dep.lower(),
                                    version=str(ver or ""), where=name,
                                    ecosystem="npm")


def _scan_native(name: str) -> Iterator[ComponentEvidence]:
    # lib/arm64-v8a/libfoo.so  ->  artifact "foo"
    parts = name.split("/")
    if len(parts) >= 2 and parts[0] == "lib" and parts[-1].endswith(".so"):
        base = parts[-1][:-3]
        if base.startswith("lib"):
            base = base[3:]
        base = base.lower()
        if base and base not in _NATIVE_SKIP:
            yield ComponentEvidence("native", base, where=name)


def extract_from_text(name: str, text: str) -> list[ComponentEvidence]:
    """Harvest component evidence from a single text entry (pure function)."""
    out: list[ComponentEvidence] = []
    if posixpath.basename(name) == "package.json":
        out.extend(_scan_package_json(name, text))
    out.extend(_scan_text(name, text))
    return _dedup(out)


def extract_components(zip_path: str, *, max_bytes: int = 2_000_000) -> list[ComponentEvidence]:
    """Open an APK/ZIP and harvest all component evidence. Offline, read-only."""
    found: list[ComponentEvidence] = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for entry in zf.namelist():
            if entry.endswith("/"):
                continue
            low = entry.lower()
            # native libs + versioned js are name-only signals (no read needed)
            found.extend(_scan_native(entry))
            found.extend(_scan_js_entry(entry))
            if not low.endswith(_TEXT_SUFFIXES):
                continue
            if entry == "AndroidManifest.xml":
                continue  # binary
            try:
                info = zf.getinfo(entry)
                if info.file_size > max_bytes:
                    continue
                text = zf.read(entry).decode("utf-8", "replace")
            except (KeyError, zipfile.BadZipFile, OSError):  # pragma: no cover
                continue
            found.extend(extract_from_text(entry, text))
    return _dedup(found)


def _dedup(items: Iterable[ComponentEvidence]) -> list[ComponentEvidence]:
    seen: set[tuple] = set()
    out: list[ComponentEvidence] = []
    for it in items:
        key = (it.kind, it.name, it.version, it.where)
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


def split_evidence(items: Iterable[ComponentEvidence]):
    """Partition evidence into (advisory_ids, package_names) for DB lookup."""
    advisories: list[str] = []
    packages: list[ComponentEvidence] = []
    for it in items:
        if it.kind in ("cve", "ghsa"):
            advisories.append(it.name)
        else:
            packages.append(it)
    return advisories, packages
