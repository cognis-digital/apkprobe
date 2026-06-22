"""apkprobe command-line interface.

    apkprobe scan    app.apk [--format table|json|sarif] [--min-severity MEDIUM]
                             [--scope s.json --key-env SCOPEWARD_KEY]
    apkprobe profile app.apk [--format table|json]
    apkprobe diff    old.apk new.apk [--format table|json] [--fail-on-regression]

``scan``    runs MASVS/MASTG checks (optionally gated by scopeward).
``profile`` maps permissions to abuse vectors and scores the attack surface.
``diff``    compares two APK versions and flags security regressions, the way a
            defender vets an app *update* (supply-chain / update-time review).
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
