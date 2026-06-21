from apkprobe.secrets import scan_text


def test_detects_google_api_key():
    text = 'apiKey="AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"'
    hits = scan_text(text, "strings.xml")
    assert any(h.kind == "Google API Key" for h in hits)


def test_detects_aws_key():
    hits = scan_text("AKIAIOSFODNN7EXAMPLE", "config.json")
    assert any(h.kind == "AWS Access Key ID" for h in hits)


def test_detects_private_key_block():
    hits = scan_text("-----BEGIN RSA PRIVATE KEY-----\nMII...", "key.pem")
    assert any(h.kind == "Private Key Block" for h in hits)


def test_sample_is_redacted():
    hits = scan_text("AKIAIOSFODNN7EXAMPLE", "x")
    assert "…" in hits[0].sample
    assert hits[0].sample != "AKIAIOSFODNN7EXAMPLE"


def test_clean_text_no_hits():
    assert scan_text("just some harmless configuration text", "x") == []
