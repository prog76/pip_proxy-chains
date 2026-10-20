# proxychains

Tag-matched proxy chain egress for Python — pool loading, loopback forwarders,
pinned exits, rotation, per-verdict quarantine. **Stdlib-only, zero
dependencies, Python ≥ 3.10.**

## Install

```bash
# pinned by tag, tarball (no git needed — container-friendly):
pip install "proxychains @ https://github.com/prog76/pip_proxy-chains/archive/refs/tags/v0.3.0.tar.gz"
# or, with git available:
pip install "proxychains @ git+https://github.com/prog76/pip_proxy-chains@v0.3.0"
```

## What it does

- **Pool** — load proxies from a file or URL (checker-export JSON:
  `{"proxies": [{"proxy": "host:port", "scheme": "http|https|socks5|socks5h", "tags": [...]}]}`),
  periodic atomic refresh with last-good retention, AND-match tag selection
  (with `-tag` negation).
- **Forwarder** — one loopback HTTP-CONNECT listener per pinned chain
  (`httpx → 127.0.0.1:<ephemeral> → [entry] → exit → target`), POST-body
  fix included, optional bind gate (LAN bind requires Basic credentials).
- **Pins & rotation** — one exit per (account, purpose), optionally
  session-scoped with TTL + LRU cap; dead exits rotate with bounded retries.
- **Per-verdict quarantine** — `VERDICT_SERVES / BUSY / STALE / GATED / DEAD`;
  consumers decide the TTLs (e.g. gate = hours, dead = minutes, rate = shorter).
- **Pluggable failure policy** — `FailurePlan` + `classify()`: applications
  register their own HTTP status/body rules without the package knowing
  about them.
- **Redacted status** — `status()` masks userinfo and IP octets: safe to
  ship to logs/dashboards.

## Quick start

```python
from proxychains import ChainsConfig, ProxyChains

chains = ProxyChains(
    ChainsConfig(path="/etc/proxies.json"),   # checker-export feed
    tags_for=lambda account, purpose: ["alive", "ok:example.com"],
)
url = chains.egress("acct/x", "api")   # http://127.0.0.1:<listener>
status = chains.status()               # redacted pin/quarantine/pool summary
chains.close()
```

Application seam: `tags_for` / `explicit_for` callables, an optional
`setup_error` exception class, and registered `classify()` rules — quarantine
scopes and pin keys are opaque strings chosen by the caller.

## Tests

```bash
pip install ".[dev]" && pytest
```

No external network: every socket binds to `127.0.0.1`.

## License

MIT — use it freely.
