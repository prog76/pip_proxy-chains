# `Resolver.status()` warm/works — counts only (2026-10-19)

## Why

The panel's egress summary only needs to know **how many** exits are warm
(preflight-verified within TTL) and **how many** "really work" (persistent
`works` tag). Shipping the full per-exit URL collections in `status()` bloats
the `/admin/proxies` payload for no benefit — and exit URLs are meant to stay
masked in observability output anyway.

## What changed

`Resolver.status()` (`src/proxychains/resolver.py`) now returns `warm` and
`works` as **per-scope count maps** instead of exit collections:

```python
# preflight warm/works COUNTS per scope. Counts only -- the panel just
# needs how many exits are warm/verified, never the exit list.
ttl = max(1, int(self._cfg.preflight_ttl or 300))
now = time.monotonic()
with self._warm_lock:
    warm_scopes = {
        scope: sum(1 for at in exits.values() if now - at <= ttl)
        for scope, exits in self._warm.items()
    }
    # persistent works (no TTL): every exit proven to serve, until a
    # later probe disproves it.
    works_scopes = {scope: len(exits) for scope, exits in self._works.items()}
```

Both are emitted as `{"<scope>": n}`, with empty/zero scopes filtered out:

```python
"warm": {scope: n for scope, n in sorted(warm_scopes.items()) if n},
"works": {scope: n for scope, n in sorted(works_scopes.items()) if n},
```

## Contract

- `warm[scope]` — exits whose preflight mark is younger than `preflight_ttl`
  (TTL-bound; an entry stops counting once it goes stale).
- `works[scope]` — exits proven to serve, with **no TTL**; cleared only when a
  later probe fails.
- Scopes are the egress quarantine scopes (e.g. account / session).

Consumers fold the per-scope maps into their own display counts (e.g. a
status panel showing warm/verified exits per scope), optionally paired with
a preflight-trigger endpoint reporting `warm` / `works_total` counts.
