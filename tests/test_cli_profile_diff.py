"""CLI tests for the `profile` and `diff` subcommands."""

from __future__ import annotations

import json

from apkprobe.cli import main, build_parser


# --- profile --------------------------------------------------------------

def test_cli_profile_text(apk_path, capsys):
    rc = main(["profile", apk_path])
    out = capsys.readouterr().out
    assert "risk score:" in out
    assert "com.acme.app" in out
    assert rc in (0, 1)


def test_cli_profile_json(apk_path, capsys):
    main(["profile", apk_path, "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["package"] == "com.acme.app"
    assert "score" in data and "grade" in data
    assert isinstance(data["capabilities"], list)


def test_cli_profile_format_json(apk_path, capsys):
    main(["profile", apk_path, "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert "vectors" in data


def test_cli_profile_bad_path(capsys, tmp_path):
    rc = main(["profile", str(tmp_path / "nope.apk")])
    assert rc == 1
    assert "error:" in capsys.readouterr().err


# --- diff -----------------------------------------------------------------

def test_cli_diff_text_regressed(old_apk_path, new_apk_path, capsys):
    rc = main(["diff", old_apk_path, new_apk_path])
    out = capsys.readouterr().out
    assert "REGRESSED" in out
    assert "regressions" in out
    assert rc == 0  # no --fail-on-regression


def test_cli_diff_fail_on_regression(old_apk_path, new_apk_path, capsys):
    rc = main(["diff", old_apk_path, new_apk_path, "--fail-on-regression"])
    assert rc == 1


def test_cli_diff_json(old_apk_path, new_apk_path, capsys):
    main(["diff", old_apk_path, new_apk_path, "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "REGRESSED"
    assert data["regression_count"] >= 1
    assert isinstance(data["deltas"], list)


def test_cli_diff_same_apk_unchanged(old_apk_path, capsys):
    rc = main(["diff", old_apk_path, old_apk_path, "--fail-on-regression"])
    out = capsys.readouterr().out
    assert "no manifest-level changes" in out or "UNCHANGED" in out
    assert rc == 0


def test_cli_diff_bad_path(old_apk_path, capsys, tmp_path):
    rc = main(["diff", old_apk_path, str(tmp_path / "nope.apk")])
    assert rc == 1
    assert "error:" in capsys.readouterr().err


def test_cli_diff_detects_new_secret(old_apk_path, new_apk_path, capsys):
    main(["diff", old_apk_path, new_apk_path, "--json"])
    data = json.loads(capsys.readouterr().out)
    kinds = {d["kind"] for d in data["deltas"]}
    assert "secret.added" in kinds


# --- parser wiring --------------------------------------------------------

def test_parser_has_all_subcommands():
    parser = build_parser()
    # argparse stores subparser choices
    sub = [a for a in parser._actions if hasattr(a, "choices") and a.choices]
    names = set()
    for a in sub:
        if a.choices and "scan" in a.choices:
            names = set(a.choices)
    assert {"scan", "profile", "diff"} <= names


def test_no_command_prints_help(capsys):
    rc = main([])
    assert rc == 1
