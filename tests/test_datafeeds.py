"""Offline tests for the data-feed manager (apkprobe.datafeeds).

These never hit the network. They exercise the catalog, the on-disk cache
(via COGNIS_FEEDS_CACHE), offline serving, and the air-gap snapshot round-trip.
"""

from __future__ import annotations

import json

import pytest

from apkprobe import datafeeds


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("COGNIS_FEEDS_CACHE", str(tmp_path / "feeds-cache"))
    yield


# --- catalog ----------------------------------------------------------------- #
def test_catalog_loads():
    cat = datafeeds.load_catalog()
    assert "feeds" in cat
    assert len(cat["feeds"]) >= 10


def test_catalog_has_core_vuln_feeds():
    ids = {f["id"] for f in datafeeds.list_feeds()}
    for needed in ("cisa-kev", "epss", "osv", "nvd-cve", "github-advisories"):
        assert needed in ids


def test_list_feeds_domain_filter():
    vuln = datafeeds.list_feeds(domain="vuln")
    assert vuln
    assert all(f.get("domain") == "vuln" for f in vuln)


def test_every_feed_has_url_and_name():
    for f in datafeeds.list_feeds():
        assert f.get("url"), f
        assert f.get("name"), f
        assert f.get("id"), f


def test_cache_dir_created():
    d = datafeeds.cache_dir()
    assert d.exists()
    assert d.is_dir()


# --- offline serving --------------------------------------------------------- #
def test_get_offline_uncached_raises():
    with pytest.raises(FileNotFoundError):
        datafeeds.get("cisa-kev", offline=True)


def test_cached_age_none_when_absent():
    assert datafeeds.cached_age_hours("cisa-kev") is None


def test_get_offline_serves_cache(tmp_path):
    # simulate a previously-fetched feed by writing the cache directly
    data_path, meta_path = datafeeds._paths("osv")
    payload = {"vulns": [{"id": "OSV-TEST-1"}]}
    data_path.write_bytes(json.dumps(payload).encode())
    import time
    meta_path.write_text(json.dumps({"feed": "osv", "fetched_at": time.time(),
                                      "bytes": 10, "format": "json"}))
    served = datafeeds.get("osv", offline=True)
    assert served == payload


def test_cached_age_after_write():
    data_path, meta_path = datafeeds._paths("epss")
    data_path.write_bytes(b"x")
    import time
    meta_path.write_text(json.dumps({"fetched_at": time.time()}))
    age = datafeeds.cached_age_hours("epss")
    assert age is not None
    assert age < 1.0


# --- air-gap snapshot round-trip --------------------------------------------- #
def test_snapshot_export_import_roundtrip(tmp_path):
    # seed two cached feeds
    for fid in ("cisa-kev", "osv"):
        dp, mp = datafeeds._paths(fid)
        dp.write_bytes(b'{"ok":true}')
        mp.write_text(json.dumps({"feed": fid, "fetched_at": 1.0}))
    archive = tmp_path / "snap.tar.gz"
    n = datafeeds.snapshot_export(str(archive))
    assert n == 2
    assert archive.exists()

    # wipe the cache, then import
    for fid in ("cisa-kev", "osv"):
        dp, mp = datafeeds._paths(fid)
        dp.unlink()
        mp.unlink()
    imported = datafeeds.snapshot_import(str(archive))
    assert imported == 2
    dp, _ = datafeeds._paths("osv")
    assert dp.read_bytes() == b'{"ok":true}'


def test_snapshot_export_empty_cache(tmp_path):
    archive = tmp_path / "empty.tar.gz"
    n = datafeeds.snapshot_export(str(archive))
    assert n == 0


# --- CLI passthrough --------------------------------------------------------- #
def test_cli_list(capsys):
    code = datafeeds.main(["list"])
    out = capsys.readouterr().out
    assert "cisa-kev" in out
    assert code == 0


def test_cli_get_offline_uncached(capsys):
    code = datafeeds.main(["get", "cisa-kev", "--offline"])
    err = capsys.readouterr().err
    assert code == 1
    assert "cisa-kev" in err
