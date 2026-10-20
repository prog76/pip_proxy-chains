"""Package smoke: install, version, public exports, pool round-trip."""
from __future__ import annotations

import json

import proxychains


def test_version_matches_release():
    assert proxychains.__version__ == "0.3.0"


def test_public_exports_present():
    for name in (
        "ChainPool",
        "ProxyChains",
        "ChainsConfig",
        "QuarantineStore",
        "ProxySetupError",
        "FailurePlan",
        "classify",
        "VERDICT_SERVES",
        "VERDICT_BUSY",
        "VERDICT_STALE",
        "VERDICT_GATED",
        "VERDICT_DEAD",
        "mask_host",
        "masked_url",
    ):
        assert hasattr(proxychains, name), name


def test_pool_load_and_tag_match(tmp_path):
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"proxies": [
        {"proxy": "198.51.100.7:8080", "scheme": "http", "tags": ["alive"]},
        {"proxy": "198.51.100.8:8080", "scheme": "socks4", "tags": ["alive"]},
    ]}), encoding="utf-8")
    pool = proxychains.ChainPool(str(feed), refresh=1)
    assert [e.url for e in pool.matches(["alive"])] == ["http://198.51.100.7:8080"]
