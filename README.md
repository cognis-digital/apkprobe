# apkprobe

**Android APK static security analyzer — MASTG-aligned, zero dependencies.**

`apkprobe` opens an APK, decodes its **binary** `AndroidManifest.xml` with a
from-scratch AXML decoder (no `aapt`, no `apktool`, no third-party libraries),
runs a set of checks mapped to **MASVS** controls and **MASTG** test ids, scans
shipped resources for embedded secrets, and reports the signing scheme.

It does three things:

| Subcommand | Question it answers |
|---|---|
| `apkprobe scan`    | Which MASVS/MASTG controls are missing? (table / JSON / **SARIF**) |
| `apkprobe profile` | How exposed is this app, and through what abuse vectors? (**risk score 0–100**) |
| `apkprobe diff`    | This is an *update* of an app I already vetted — **did it get worse?** |

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
apkprobe scan app.apk --format json --min-severity MEDIUM

# SARIF for GitHub code-scanning / any SARIF dashboard
apkprobe scan app.apk --format sarif > apkprobe.sarif

# Gated by an authorized engagement scope (refuses unlisted packages)
export SCOPEWARD_KEY=...           # the engagement key
apkprobe scan app.apk --scope engagement.json

# Attack-surface profile + bounded risk score (exits non-zero on grade E/F)
apkprobe profile app.apk
apkprobe profile app.apk --json

# Diff two versions for security regressions (CI update-gate)
apkprobe diff old.apk new.apk
apkprobe diff old.apk new.apk --fail-on-regression
```

### Attack-surface profile & version diffing

`profile` maps every requested permission to the **capability** it grants and a
documented **abuse vector** (surveillance, exfiltration, billing fraud, device
admin, accessibility abuse, overlay phishing…), enumerates the exported **IPC
surface**, and rolls it into a bounded **risk score (0–100)** with a fully
attributed breakdown — no opaque number.

`diff` compares two APK versions and classifies every change as a security
**regression**, an **improvement**, or neutral — the way a defender vets an app
*update*. It catches the supply-chain shapes single-version scanning misses: a
silent flip to `debuggable`, a newly added `READ_SMS`, a freshly exported
unguarded provider, a signing-key rotation, or a new embedded secret. With
`--fail-on-regression` it gates every update in CI.

Full walkthrough, the permission knowledge base, scoring model, and an honest
limits section: **[docs/attack-surface-and-diffing.md](docs/attack-surface-and-diffing.md)**.

Exit code is non-zero when any **HIGH+** finding is present, so it drops
straight into a CI gate. Upload the SARIF to GitHub code scanning:

```yaml
- run: apkprobe scan app.apk --format sarif > apkprobe.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: apkprobe.sarif }
```

Each MASVS/MASTG check becomes a SARIF rule (with a `mas.owasp.org` help link),
each finding a result with a stable fingerprint for cross-run dedup.

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
apk.py            ZIP container: locate manifest, detect v1/v2+ signing, yield text entries
 └ axml.py        binary AXML decoder (string pool, namespaces, elements, typed attrs)
 └ manifest.py    decoded tree -> AppManifest (package, sdk, perms, flags, components)
rules.py          MASVS/MASTG checks -> Finding[]
secrets.py        high-signal credential patterns
attacksurface.py  permission->capability->vector KB + bounded risk score (profile)
diff.py           version-to-version regression detection (diff)
analyzer.py       orchestration + optional scopeward gating
sarif.py          SARIF 2.1.0 export
cli.py            scan / profile / diff subcommands
```

`Finding`/`Severity` come from `scopeward` when installed, so apkprobe results
merge with the rest of the suite into one engagement report.

## Scope of use

For analyzing apps **you are authorized to assess** — your own apps, client apps
under a signed engagement, lab/CTF targets. The `--scope` flag exists to keep it
that way. Static analysis only; `apkprobe` does not modify or repackage APKs.

## License

Cognis Open Collaboration License (COCL) v1.0. See [LICENSE](LICENSE).
