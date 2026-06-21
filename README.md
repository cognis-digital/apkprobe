# apkprobe

**Android APK static security analyzer — MASTG-aligned, zero dependencies.**

`apkprobe` opens an APK, decodes its **binary** `AndroidManifest.xml` with a
from-scratch AXML decoder (no `aapt`, no `apktool`, no third-party libraries),
runs a set of checks mapped to **MASVS** controls and **MASTG** test ids, scans
shipped resources for embedded secrets, and reports the signing scheme.

It is part of the Cognis mobile-security suite and integrates with
[`scopeward`](../scopeward): point it at a signed engagement scope and it will
refuse to analyze any package that isn't an authorized target.

## Why it's different

Most "APK scanners" shell out to `aapt`/`apktool` or pull in heavy SDKs.
`apkprobe` decodes compiled AXML itself in pure Python (`apkprobe/axml.py`), so
it runs anywhere Python runs — CI containers, air-gapped review boxes, a laptop
— with **nothing to install**.

## Install

```bash
pip install -e .                 # standalone
pip install -e ".[scope]"        # with scopeward engagement gating
pip install -e ".[dev]"          # + pytest
```

## Use

```bash
# Quick scan, human-readable
apkprobe scan app.apk

# Machine-readable, only MEDIUM and above
apkprobe scan app.apk --json --min-severity MEDIUM

# Gated by an authorized engagement scope (refuses unlisted packages)
export SCOPEWARD_KEY=...           # the engagement key
apkprobe scan app.apk --scope engagement.json
```

Exit code is non-zero when any **HIGH+** finding is present, so it drops
straight into a CI gate.

### Example output

```
package: com.acme.app
signing: v1 (JAR)
findings: 9 (>= INFO)
  [HIGH    ] Application is debuggable
             MASVS-RESILIENCE-2 / MASTG-TEST-0026 — android:debuggable="true"
  [HIGH    ] Cleartext (HTTP) traffic permitted
             MASVS-NETWORK-1 / MASTG-TEST-0019 — android:usesCleartextTraffic="true"
  [HIGH    ] Possible embedded secret: Google API Key
             MASVS-STORAGE-1 / MASTG-TEST-0011 — res/raw/cfg.json: AIzaSy…qsHI
  [MEDIUM  ] Exported activity without permission: .MainActivity
  ...
```

## What it checks

| Check | MASVS | MASTG |
|-------|-------|-------|
| Debuggable build | MASVS-RESILIENCE-2 | MASTG-TEST-0026 |
| ADB backup allowed | MASVS-STORAGE-2 | MASTG-TEST-0009 |
| Cleartext traffic permitted | MASVS-NETWORK-1 | MASTG-TEST-0019 |
| Missing Network Security Config | MASVS-NETWORK-2 | MASTG-TEST-0020 |
| Exported component without permission | MASVS-PLATFORM-1 | MASTG-TEST-0024 |
| Sensitive permission requested | MASVS-PLATFORM-1 | MASTG-TEST-0024 |
| Embedded secret in resources | MASVS-STORAGE-1 | MASTG-TEST-0011 |
| Unsigned / undetected signature | MASVS-RESILIENCE-1 | — |
| Low minSdkVersion | MASVS-RESILIENCE-1 | — |

## Architecture

```
apk.py        ZIP container: locate manifest, detect v1/v2+ signing, yield text entries
 └ axml.py    binary AXML decoder (string pool, namespaces, elements, typed attrs)
 └ manifest.py decoded tree -> AppManifest (package, sdk, perms, flags, components)
rules.py      MASVS/MASTG checks -> Finding[]
secrets.py    high-signal credential patterns
analyzer.py   orchestration + optional scopeward gating
cli.py        scan command
```

`Finding`/`Severity` come from `scopeward` when installed, so apkprobe results
merge with the rest of the suite into one engagement report.

## Scope of use

For analyzing apps **you are authorized to assess** — your own apps, client apps
under a signed engagement, lab/CTF targets. The `--scope` flag exists to keep it
that way. Static analysis only; `apkprobe` does not modify or repackage APKs.

## License

Cognis Open Collaboration License (COCL) v1.0. See [LICENSE](LICENSE).
