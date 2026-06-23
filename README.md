# apkprobe

**Android APK static security analyzer — MASTG-aligned, zero dependencies.**

`apkprobe` opens an APK, decodes its **binary** `AndroidManifest.xml` with a
from-scratch AXML decoder (no `aapt`, no `apktool`, no third-party libraries),
runs a set of checks mapped to **MASVS** controls and **MASTG** test ids, scans
shipped resources for embedded secrets, and reports the signing scheme.

It runs in two modes. **Passive** (the default) is fully offline: hand it bytes
you already have and it reads them — no network, no device, no side effects.
**Active** (opt-in, authorization-gated) pulls an installed app off a device
**you own** so it can then be analyzed passively.

### Passive subcommands (offline, default)

| Subcommand | Question it answers |
|---|---|
| `apkprobe scan`      | Which MASVS/MASTG controls are missing? (table / JSON / **SARIF**) |
| `apkprobe profile`   | How exposed is this app, and through what abuse vectors? (**risk score 0–100**) |
| `apkprobe diff`      | This is an *update* of an app I already vetted — **did it get worse?** |
| `apkprobe inventory` | What's the IPC surface — which components are exported and unguarded? |
| `apkprobe triage`    | Offline triage of a captured `pm list packages` dump (name-shape heuristics) |
| `apkprobe vulns`     | Which **known CVEs** are tied to components this APK ships? (vs. a **bundled ~262k-record OSV DB**, offline) |
| `apkprobe feeds`     | Manage the offline **OSV/NVD/GHSA/KEV edge cache** (refresh online, serve offline, air-gap snapshot) |

### Active subcommand (authorization-gated, OFF by default)

| Subcommand | Question it answers |
|---|---|
| `apkprobe pull`      | Copy an installed app off a **connected device I own** (via ADB) to scan it |

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
# from a clone (recommended — ships the bundled vuln DB + feed catalog)
git clone https://github.com/cognis-digital/apkprobe && cd apkprobe
pip install -e .                 # standalone, zero runtime deps
pip install -e ".[scope]"        # with scopeward engagement gating
pip install -e ".[dev]"          # + pytest

# or straight from PyPI/VCS
pip install apkprobe
```

The bundled **~262k-record OSV vulnerability DB** (`cognis_vulndb.jsonl.gz`,
~6.4 MB) and the **35-feed catalog** (`data_feeds_2026.json`) ship inside the
package, so `apkprobe vulns` and `apkprobe feeds` work offline immediately after
install — no first-run download.

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

# IPC surface inventory (offline)
apkprobe inventory app.apk
apkprobe inventory app.apk --json

# Offline triage of a captured package list (e.g. a saved `pm list packages`)
apkprobe triage packages.txt --allow com.corp.cleaner

# Known-CVE enrichment: match the APK's shipped components against the
# bundled ~262k-record OSV vulnerability DB (fully offline; exits non-zero
# on a HIGH/CRITICAL match so it gates CI)
apkprobe vulns app.apk
apkprobe vulns app.apk --cve-only --min-confidence exact-advisory
apkprobe vulns app.apk --json > apkprobe-vulns.json
```

## Known-CVE enrichment against a bundled OSV DB (offline)

A manifest scan tells you how an app is configured; it does not tell you whether
the **libraries the app ships are already known-vulnerable**. `apkprobe vulns`
closes that gap — entirely offline.

It harvests **real component evidence** out of the APK ZIP (no fabrication, no
fingerprint guessing):

* **CVE / GHSA ids** the app names verbatim in any text resource — changelogs,
  `third_party_licenses` / OSS-credits blobs, SBOMs. (Strongest signal: the app
  itself names the advisory.)
* **Maven coordinates** (`group:artifact:version`) in dependency listings;
* **Bundled JavaScript libraries** — `foo-1.2.3.min.js` and `package.json`
  `name`/`dependencies` for Cordova / Capacitor / React-Native apps (npm);
* **Native shared objects** — `lib/<abi>/lib<name>.so` artifact names.

…then correlates that evidence against a **bundled, consolidated OSV corpus of
~262,000 real vulnerabilities** (`apkprobe/cognis_vulndb.jsonl.gz`, ~6.4 MB,
spanning npm / Maven / Go / PyPI / RubyGems / crates.io / NuGet). Every hit is
ranked by confidence (`exact-advisory` > `coordinate` > `artifact-name` >
`native-name`), banded by severity (the **CVSS v3.x base score is computed from
the vector** — Log4Shell resolves to `10.0` → CRITICAL), and attributed to the
exact APK entry the evidence came from. No network. No key. Works air-gapped the
moment the repo is cloned.

```
$ apkprobe vulns app.apk
package: com.acme.app
vuln DB: 262351 records (bundled OSV, offline)
evidence: 9 component(s) harvested from the APK
matches:  83 hit(s) across 71 distinct advisor(ies)
worst severity: CRITICAL
  [exact-advisory] CVE-2021-44228  ->  CVE-2021-44228 (CRITICAL)
                   Remote code injection in Log4j
                   via assets/third_party_licenses.txt
  [coordinate    ] com.fasterxml.jackson.core:jackson-databind@2.9.8  ->  CVE-2018-14719 (CRITICAL)
                   Arbitrary Code Execution in jackson-databind
                   via assets/third_party_licenses.txt
  ...
```

The command exits **non-zero on any HIGH/CRITICAL** match, so it drops into a CI
supply-chain gate next to `scan` and `diff`. Filter with `--cve-only`,
`--min-confidence <level>`, and `--json` for machine output.

> **Honest scope.** The bundled corpus is *name/advisory-keyed* (compact OSV), so
> a package match means "this component is named in N known advisories", not a
> version-resolved exploitability verdict — confidence labels make that explicit.
> The DB is **real OSV data**; nothing is fabricated. For version-precise range
> resolution, refresh the full OSV/NVD range data into an edge cache (below).

### Edge / air-gap intelligence refresh

`apkprobe feeds` (backed by `apkprobe/datafeeds.py` + the keyless
`data_feeds_2026.json` catalog of 35 real feeds — CISA KEV, EPSS, OSV, NVD,
GHSA, MITRE ATT&CK STIX, NIST 800-53 OSCAL, abuse.ch C2/IOC, …) keeps the
intelligence current on **disconnected / edge / field gear**:

```bash
# On a connected box: refresh feeds into the local cache
apkprobe feeds list --domain vuln
apkprobe feeds update osv nvd-cve github-advisories
apkprobe feeds bulk nvd-cve --max 250000        # paginate the full NVD set to disk

# Sneakernet the cache into an air-gapped enclave
apkprobe feeds snapshot-export feeds.tar.gz
#   ...carry feeds.tar.gz across the air gap...
apkprobe feeds snapshot-import feeds.tar.gz
apkprobe feeds get cisa-kev --offline           # serve from cache, never touch the network
```

Standard-library only (`urllib`), disk-cached with per-feed freshness metadata,
`--offline` serves cache and never opens a socket. The cache location is set by
`COGNIS_FEEDS_CACHE` (default `~/.cache/cognis-feeds`). `apkprobe vulns` itself
never hits the network — only `feeds update`/`bulk` do, and only when you run
them on a connected box.

## Active mode (authorized-use only)

> **⚠ AUTHORIZED USE ONLY.** `apkprobe pull` touches a real, physically
> connected device over ADB. Use it **only** on devices you own or are
> explicitly authorized to assess. It performs *defensive acquisition only* —
> it copies an installed app off the device so you can analyze it. There is **no
> exploitation, no payload, no remote target, no C2**. You are responsible for
> having authorization for every device serial you name.

Active mode is **OFF by default** and gated on three things, all required:

1. `--authorized` — an explicit flag confirming you have authorization.
2. `--device-allowlist <serial> [...]` — the device serial(s) you may touch.
   Any device whose serial is not on the allowlist is **refused**; the tool
   never acts on "whatever happens to be plugged in".
3. A **rate limit** (`--rate-limit`, default 1 op/sec) so it can never hammer a
   device.

Every active run prints a loud authorized-use banner naming the device and
package before doing anything, and serials/package names are validated so they
can never smuggle a shell argument. ADB talks only to the local loopback
daemon — active mode never opens a socket to an external host.

```bash
# List authorized, connected devices (must be on the allowlist)
adb devices                       # find your serial, e.g. SERIAL123

# Pull an installed app off a device you own, then scan it passively
apkprobe pull com.acme.app \
  --authorized \
  --device-allowlist SERIAL123 \
  --out-dir ./pulled
apkprobe scan ./pulled/com.acme.app.apk
```

Without `--authorized` and a `--device-allowlist`, `pull` refuses and exits
non-zero. Split APKs are pulled as `com.acme.app.0.apk`, `…1.apk`, etc.

## Language ports

The **core check** — the MASVS/MASTG manifest rule engine — is also ported to
Go, Rust, TypeScript, and Kotlin under [`ports/`](ports/), so it can run inside
non-Python toolchains. Each port consumes a **normalized manifest JSON**
(produced by `apkprobe.normalize.normalize_manifest`) and emits the same
findings as the Python reference, finding-for-finding. The TypeScript port also
mirrors the **component-evidence harvester + CVSS scoring** from `vulns` (see
`ports/ts/src/vulnmatch.ts`). All ports are **verified on GitHub-hosted CI
runners** (`.github/workflows/ports.yml`) — the binary-AXML decoder and the
bundled OSV DB stay in the Python reference implementation.

| Port | Dir | Build / test |
|------|-----|--------------|
| Python (reference) | `apkprobe/` | `python -m pytest` |
| Go | `ports/go` | `go test ./...` |
| Rust | `ports/rust` | `cargo test` |
| TypeScript | `ports/ts` | `npm install && npm run build && npm test` |
| Kotlin | `ports/kotlin` | `kotlinc … && java -cp apkprobe-kt.jar TestKt` |

```bash
# Pipe a normalized manifest into any port; they agree on the findings
apkprobe scan app.apk --emit-manifest | (cd ports/go && go run .)
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
passive.py        offline IPC inventory + package-list triage (no network/device)
active.py         authorization-gated ADB device pull (OFF by default, gated)
normalize.py      normalized-manifest JSON contract shared with the ports
analyzer.py       orchestration + optional scopeward gating
sarif.py          SARIF 2.1.0 export
components.py     harvest CVE/GHSA refs + Maven/npm/native component evidence (offline)
vulndb_local.py   bundled ~262k-record OSV corpus (lazy gz, indexed by CVE/package)
vulnmatch.py      correlate component evidence -> OSV DB + CVSS scoring/banding
datafeeds.py      OSV/NVD/GHSA/KEV edge cache (refresh online, serve offline, air-gap snapshot)
cli.py            scan / profile / diff / inventory / triage / vulns / feeds / pull
ports/            Go + Rust + TypeScript + Kotlin ports of the core rule engine (CI-verified)
```

`Finding`/`Severity` come from `scopeward` when installed, so apkprobe results
merge with the rest of the suite into one engagement report.

## Scope of use

For analyzing apps **you are authorized to assess** — your own apps, client apps
under a signed engagement, lab/CTF targets. The `--scope` flag exists to keep it
that way. apkprobe does not modify or repackage APKs.

Passive mode is static analysis only. **Active mode** (`apkprobe pull`) reads an
installed app off a **device you own / are authorized to assess**; it is OFF by
default and gated on `--authorized` + a `--device-allowlist` + a rate limit
(see *Active mode* above). It is defensive acquisition only — no exploitation,
no payload, no remote target. You are responsible for authorization on every
device serial you name.

## License

Cognis Open Collaboration License (COCL) v1.0. See [LICENSE](LICENSE).
