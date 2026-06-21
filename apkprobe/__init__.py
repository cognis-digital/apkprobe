"""apkprobe — Android APK static security analyzer (MASTG-aligned).

Decodes the binary manifest, runs MASVS/MASTG-mapped checks, scans shipped
resources for embedded secrets, and reports the signing scheme. Integrates with
``scopeward`` so it only analyzes apps inside an authorized engagement.
"""

from .axml import parse, Element, AXMLError
from .manifest import AppManifest, Component
from .apk import Apk, ApkInfo
from .rules import analyze_manifest, Finding, Severity
from .secrets import scan_text, SecretHit
from .analyzer import analyze_apk, Report

__all__ = [
    "parse", "Element", "AXMLError",
    "AppManifest", "Component",
    "Apk", "ApkInfo",
    "analyze_manifest", "Finding", "Severity",
    "scan_text", "SecretHit",
    "analyze_apk", "Report",
]

__version__ = "0.1.0"
