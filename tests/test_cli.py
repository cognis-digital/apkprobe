from apkprobe.cli import main


def test_cli_scan_text(apk_path, capsys):
    rc = main(["scan", apk_path])
    out = capsys.readouterr().out
    assert "com.acme.app" in out
    assert "findings:" in out
    assert rc == 1  # HIGH findings present -> non-zero (CI gate)


def test_cli_scan_json(apk_path, capsys):
    main(["scan", apk_path, "--json"])
    import json
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["package"] == "com.acme.app"
    assert data["finding_count"] >= 1


def test_cli_min_severity_filter(apk_path, capsys):
    main(["scan", apk_path, "--json", "--min-severity", "CRITICAL"])
    import json
    data = json.loads(capsys.readouterr().out)
    # nothing in the fixture is CRITICAL
    assert all(f["severity"] == "CRITICAL" for f in data["findings"])


def test_cli_version(capsys):
    rc = main(["--version"])
    assert rc == 0
    assert capsys.readouterr().out.strip()
