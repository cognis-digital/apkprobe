# apkprobe language ports

These are independent ports of apkprobe's **core check** — the MASVS/MASTG
manifest rule engine (`apkprobe/rules.py`). Each port takes a **normalized
manifest JSON** on stdin (the shape produced by the Python
`AppManifest`/`Component` model) and emits the same findings as JSON, so all
ports agree finding-for-finding.

They exist so the core defensive check can run inside non-Python toolchains
(Go services, Rust pipelines, Node/TS CI) without shelling out to Python. The
heavyweight binary-AXML decoder stays in the Python reference implementation;
ports consume already-decoded manifest JSON.

| Port | Dir | Build / test |
|------|-----|--------------|
| Go | `ports/go` | `go test ./...` |
| Rust | `ports/rust` | `cargo test` |
| TypeScript | `ports/ts` | `npm ci && npm test` |
| Kotlin | `ports/kotlin` | `kotlinc Rules.kt Main.kt Test.kt -include-runtime -d apkprobe-kt.jar && java -cp apkprobe-kt.jar TestKt` |

All four are verified on GitHub-hosted runners by `.github/workflows/ports.yml`.
The Go/Rust/Kotlin toolchains were **not** built locally — they are CI-verified.
Kotlin is the native Android language, so it is the natural host for these
manifest checks; the port is stdlib-only (it bundles a tiny JSON reader) and
compiles with a bare `kotlinc` — no Gradle.

## Normalized manifest JSON

```json
{
  "package": "com.acme.app",
  "min_sdk": 21,
  "target_sdk": 33,
  "debuggable": true,
  "allow_backup": true,
  "uses_cleartext_traffic": true,
  "network_security_config": "",
  "permissions": ["android.permission.READ_SMS"],
  "components": [
    {"kind": "activity", "name": ".Main", "exported": true,
     "has_permission": false, "intent_filters": 1}
  ]
}
```

`uses_cleartext_traffic` may be `true`, `false`, or `null` (unset).

## Finding shape

```json
{"title": "...", "severity": "HIGH", "masvs": "MASVS-...",
 "mastg_test": "MASTG-TEST-....", "evidence": "..."}
```
