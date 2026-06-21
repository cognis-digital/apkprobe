"""apkprobe command-line interface.

    apkprobe scan app.apk [--format table|json|sarif] [--min-severity MEDIUM]
                          [--scope s.json --key-env SCOPEWARD_KEY]

With ``--scope`` the analysis is gated by scopeward: the APK's package must be
an authorized target or the run is refused.
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
