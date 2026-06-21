"""SARIF 2.1.0 export — valid structure, GitHub-code-scanning ready."""

import json

from apkprobe.analyzer import analyze_apk
from apkprobe.sarif import to_sarif, to_sarif_json


def test_sarif_top_level_shape(apk_path):
    doc = to_sarif(analyze_apk(apk_path))
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "apkprobe"
    assert run["results"]


def test_results_have_required_fields(apk_path):
    run = to_sarif(analyze_apk(apk_path))["runs"][0]
    for r in run["results"]:
        assert r["ruleId"]
        assert r["level"] in ("error", "warning", "note")
        assert r["message"]["text"]
        assert r["partialFingerprints"]["apkprobe/v1"]
        assert r["locations"][0]["logicalLocations"][0]["name"]


def test_rules_deduped_and_referenced(apk_path):
    run = to_sarif(analyze_apk(apk_path))["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    # every result references a declared rule
    for r in run["results"]:
        assert r["ruleId"] in rule_ids
    # rules are unique
    ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids))


def test_severity_maps_to_level(apk_path):
    run = to_sarif(analyze_apk(apk_path))["runs"][0]
    # the fixture has a debuggable (HIGH) finding -> error level present
    levels = {r["level"] for r in run["results"]}
    assert "error" in levels


def test_mastg_rule_has_help_uri(apk_path):
    run = to_sarif(analyze_apk(apk_path))["runs"][0]
    mastg_rules = [r for r in run["tool"]["driver"]["rules"] if r["id"].startswith("MASTG-")]
    assert mastg_rules
    assert any("mas.owasp.org" in r.get("helpUri", "") for r in mastg_rules)


def test_to_sarif_json_parses(apk_path):
    doc = json.loads(to_sarif_json(analyze_apk(apk_path)))
    assert doc["runs"][0]["results"]


def test_cli_sarif_format(apk_path, capsys):
    from apkprobe.cli import main
    main(["scan", apk_path, "--format", "sarif"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "apkprobe"
