"""APK container reader.

An APK is a ZIP. This locates and decodes the binary ``AndroidManifest.xml``,
reports the signature scheme (v1 JAR signing via META-INF, v2+ via the APK
Signing Block), and yields text-bearing entries for the secret scanner.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from typing import Iterator

from .manifest import AppManifest

# Entry-name prefixes/suffixes worth scanning for secrets (text content)
_TEXT_SUFFIXES = (".xml", ".json", ".txt", ".properties", ".js", ".html", ".cfg", ".pem")
_APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"


@dataclass
class ApkInfo:
    manifest: AppManifest
    signature_schemes: list[str] = field(default_factory=list)
    entry_count: int = 0


class Apk:
    def __init__(self, path: str):
        self.path = path
        self._zip = zipfile.ZipFile(path, "r")

    def __enter__(self) -> "Apk":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._zip.close()

    def manifest(self) -> AppManifest:
        raw = self._zip.read("AndroidManifest.xml")
        return AppManifest.from_axml(raw)

    def signature_schemes(self) -> list[str]:
        schemes: list[str] = []
        names = self._zip.namelist()
        if any(n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))
               for n in names):
            schemes.append("v1 (JAR)")
        if self._has_signing_block():
            schemes.append("v2+/v3 (APK Signing Block)")
        return schemes

    def _has_signing_block(self) -> bool:
        try:
            with open(self.path, "rb") as fh:
                blob = fh.read()
        except OSError:  # pragma: no cover
            return False
        return _APK_SIG_BLOCK_MAGIC in blob

    def text_entries(self, max_bytes: int = 1_000_000) -> Iterator[tuple[str, str]]:
        for name in self._zip.namelist():
            if name.endswith("/"):
                continue
            if not name.lower().endswith(_TEXT_SUFFIXES):
                continue
            if name == "AndroidManifest.xml":
                continue  # binary
            try:
                info = self._zip.getinfo(name)
                if info.file_size > max_bytes:
                    continue
                data = self._zip.read(name)
            except (KeyError, zipfile.BadZipFile):  # pragma: no cover
                continue
            yield name, data.decode("utf-8", errors="replace")

    def info(self) -> ApkInfo:
        return ApkInfo(
            manifest=self.manifest(),
            signature_schemes=self.signature_schemes(),
            entry_count=len(self._zip.namelist()),
        )
