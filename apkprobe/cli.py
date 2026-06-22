"""apkprobe command-line interface.

    apkprobe scan      app.apk [--format table|json|sarif] [--min-severity MEDIUM]
                               [--scope s.json --key-env SCOPEWARD_KEY]
    apkprobe profile   app.apk [--format table|json]
    apkprobe diff      old.apk new.apk [--format table|json] [--fail-on-regression]
    apkprobe inventory app.apk [--format table|json]
    apkprobe triage    packages.txt [--allow pkg ...] [--include-system] [--json]
    apkprobe pull      <package> --authorized --device-allowlist S [--device S]

PASSIVE (default, offline, no device/network):
  ``scan``      runs MASVS/MASTG checks (optionally gated by scopeward).
  ``profile``   maps permissions to abuse vectors and scores the attack surface.
  ``diff``      compares two APK versions and flags security regressions, the way
                a defender vets an app *update* (supply-chain / update-time review).
  ``inventory`` flattens the IPC surface (exported/guarded components).
  ``triage``    offline triage of a captured ``pm list packages`` dump.

ACTIVE (authorization-gated, OFF by default):
  ``pull``      copy an installed app off a CONNECTED device you OWN (via ADB) so
                it can be scanned. Requires ``--authorized`` AND a
                ``--device-allowlist``; rate-limited; refuses out-of-scope
                devices. Defensive acquisition only — no exploitation/payload.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from .analyzer import analyze_apk
from .rules import Severity


def _build_authorizer(scope_path: str, key_env: str):
    from scopeward.scope import Scope
    from scopeward.authz import Authorizer
    key = os.environ.get(key_env)
    if not key:
        print(f"error: signing key not in env var {key_env!r}", file=sys.stderr)
        raise SystemExit(2)
    return Authorizer(Scope.load(scope_path), key)


def cmd_scan(args: argparse.Namespace) -> int:
    authorizer = None
    if args.scope:
        try:
            authorizer = _build_authorizer(args.scope, args.key_env)
        except ImportError:
            print("error: --scope requires scopeward to be installed", file=sys.stderr)
            return 2

    try:
        report = analyze_apk(args.apk, authorizer=authorizer)
    except Exception as exc:  # scopeward.ScopeViolation or parse error
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if getattr(args, "emit_manifest", False):
        # Emit the normalized manifest JSON the language ports consume.
        from .normalize import normalize_manifest_json
        print(normalize_manifest_json(report.manifest))
        return 0

    threshold = Severity.parse(args.min_severity) if args.min_severity else Severity.INFO
    findings = [f for f in report.findings if int(Severity.parse(f.severity)) >= int(threshold)]

    fmt = "json" if args.json else args.format  # --json kept for back-compat
    if fmt == "sarif":
        from .sarif import to_sarif
        # SARIF over the (severity-filtered) findings.
        filtered = report
        filtered.findings = findings
        print(json.dumps(to_sarif(filtered), indent=2))
    elif fmt == "json":
        out = report.to_dict()
        out["findings"] = [f.to_dict() for f in findings]
        print(json.dumps(out, indent=2))
    else:
        print(f"package: {report.package or '(unknown)'}")
        print(f"signing: {', '.join(report.signature_schemes) or 'NONE DETECTED'}")
        print(f"findings: {len(findings)} (>= {Severity.parse(args.min_severity or 'INFO').name})")
        for f in sorted(findings, key=lambda x: -int(Severity.parse(x.severity))):
            sev = Severity.parse(f.severity).name
            print(f"  [{sev:8}] {f.title}")
            if f.masvs:
                print(f"             {f.masvs} / {f.mastg_test or 'n/a'} — {f.evidence}")
    # Non-zero exit if any HIGH+ findings, useful in CI gates.
    return 1 if report.max_severity() >= int(Severity.HIGH) else 0


def cmd_profile(args: argparse.Namespace) -> int:
    from .attacksurface import profile, render_text
    try:
        report = analyze_apk(args.apk)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    surf = profile(report.manifest)
    if args.json or args.format == "json":
        print(json.dumps(surf.to_dict(), indent=2))
    else:
        print(render_text(surf))
    # Non-zero exit for a failing grade, so `profile` also gates CI.
    return 1 if surf.grade in ("E", "F") else 0


def cmd_diff(args: argparse.Namespace) -> int:
    from .diff import diff_reports, render_text
    try:
        old = analyze_apk(args.old)
        new = analyze_apk(args.new)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    res = diff_reports(old, new)
    if args.json or args.format == "json":
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print(render_text(res))
    if args.fail_on_regression and res.regressions():
        return 1
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    from .passive import component_inventory, render_inventory
    try:
        report = analyze_apk(args.apk)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    inv = component_inventory(report.manifest)
    if args.json or args.format == "json":
        print(json.dumps(inv.to_dict(), indent=2))
    else:
        print(render_inventory(inv))
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    from .passive import triage_package_list
    try:
        with open(args.packages, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    hits = triage_package_list(lines, allowlist=args.allow or (),
                               include_system=args.include_system)
    if args.json or args.format == "json":
        print(json.dumps([h.to_dict() for h in hits], indent=2))
    else:
        print(f"triaged {len(lines)} package line(s): {len(hits)} hit(s)")
        for h in hits:
            print(f"  [HINT] {h.package} — {h.reason}")
    return 0


def cmd_pull(args: argparse.Namespace) -> int:
    """ACTIVE mode: authorization-gated pull off a connected device."""
    from .active import (
        ActiveConfig, DeviceAcquirer, AdbCliBackend, ActiveError,
    )
    config = ActiveConfig(
        authorized=args.authorized,
        device_allowlist=tuple(args.device_allowlist or ()),
        rate_limit=args.rate_limit,
        out_dir=args.out_dir,
    )
    try:
        config.require_authorized()
    except ActiveError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    backend = AdbCliBackend(adb=args.adb)
    acq = DeviceAcquirer(backend, config)

    try:
        if args.device:
            serials = [args.device]
        else:
            serials = acq.authorized_devices()
            if not serials:
                print("error: no authorized device connected (check "
                      "--device-allowlist and that the device is plugged in)",
                      file=sys.stderr)
                return 1
        results = [acq.pull_package(s, args.package) for s in serials]
    except ActiveError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # backend/device failure
        print(f"error: {exc}", file=sys.stderr)
        return 1

    payload = [r.to_dict() for r in results]
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for r in results:
            print(f"pulled {r.package} from {r.serial}:")
            for lp in r.local_paths:
                print(f"  {lp}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="apkprobe", description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="command")
    p = sub.add_parser("scan", help="analyze an APK")
    p.add_argument("apk")
    p.add_argument("--format", choices=("table", "json", "sarif"), default="table",
                   help="output format (sarif → GitHub code-scanning)")
    p.add_argument("--json", action="store_true", help="alias for --format json")
    p.add_argument("--min-severity", default="INFO")
    p.add_argument("--scope", help="scopeward engagement scope JSON")
    p.add_argument("--key-env", default="SCOPEWARD_KEY")
    p.add_argument("--emit-manifest", action="store_true",
                   help="emit the normalized manifest JSON the language ports consume")
    p.set_defaults(func=cmd_scan)

    pp = sub.add_parser("profile", help="attack-surface profile + risk score")
    pp.add_argument("apk")
    pp.add_argument("--format", choices=("table", "json"), default="table")
    pp.add_argument("--json", action="store_true", help="alias for --format json")
    pp.set_defaults(func=cmd_profile)

    pd = sub.add_parser("diff", help="diff two APK versions for regressions")
    pd.add_argument("old")
    pd.add_argument("new")
    pd.add_argument("--format", choices=("table", "json"), default="table")
    pd.add_argument("--json", action="store_true", help="alias for --format json")
    pd.add_argument("--fail-on-regression", action="store_true",
                    help="exit non-zero if any security regression is found")
    pd.set_defaults(func=cmd_diff)

    pi = sub.add_parser("inventory", help="flatten the IPC/component surface (offline)")
    pi.add_argument("apk")
    pi.add_argument("--format", choices=("table", "json"), default="table")
    pi.add_argument("--json", action="store_true", help="alias for --format json")
    pi.set_defaults(func=cmd_inventory)

    pt = sub.add_parser("triage", help="offline triage of a captured package list")
    pt.add_argument("packages", help="file with one package per line (pm list packages dump)")
    pt.add_argument("--allow", nargs="*", default=[], help="packages never flagged")
    pt.add_argument("--include-system", action="store_true",
                    help="also consider Android system packages")
    pt.add_argument("--format", choices=("table", "json"), default="table")
    pt.add_argument("--json", action="store_true", help="alias for --format json")
    pt.set_defaults(func=cmd_triage)

    pu = sub.add_parser(
        "pull",
        help="ACTIVE (authorized-only): pull an installed app off a connected device",
    )
    pu.add_argument("package", help="package name to pull (e.g. com.acme.app)")
    pu.add_argument("--authorized", action="store_true",
                    help="REQUIRED: confirm you are authorized to touch the device(s)")
    pu.add_argument("--device-allowlist", nargs="*", default=[],
                    help="REQUIRED: serial(s) of device(s) you may touch")
    pu.add_argument("--device", help="specific device serial (must be on the allowlist)")
    pu.add_argument("--rate-limit", type=float, default=1.0,
                    help="max device operations per second (default 1.0)")
    pu.add_argument("--out-dir", default=".", help="where to write pulled APK(s)")
    pu.add_argument("--adb", default="adb", help="path to the adb binary")
    pu.add_argument("--json", action="store_true")
    pu.set_defaults(func=cmd_pull)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False):
        from . import __version__
        print(__version__)
        return 0
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
