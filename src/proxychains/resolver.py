"""Resolver -- pins, rotation, quarantine, preflight (warm-set) and status
for tag-based egress."""

from __future__ import annotations

import asyncio
import logging
import os
import random
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Sequence

from .errors import ProxySetupError
from .forwarder import (ChainListener, Proxy, _Handler, _Server,
                         _basic_auth)
from .pool import ChainPool, PoolEntry
from .util import masked_url

log = logging.getLogger(__name__)

# A stage record older than this does not belong to the attempt being judged.
_STAGE_FRESH_SECONDS = 10.0
# Default per-candidate probe budget in preflight(): must cover the
# forwarder's CONNECT timeout (12s) + TLS + a response head.
_PREFLIGHT_TIMEOUT = 25.0

# Preflight probe verdicts.  A probe may return a bool (legacy: True = serves,
# False = dead) or one of these strings; the resolver maps them onto the
# warm set and per-verdict cooldowns.
VERDICT_SERVES = "serves"   # proven: warm + works
VERDICT_BUSY = "busy"       # 429-class: serves, rate-limited upstream
VERDICT_STALE = "stale"     # billing/retired-model verdict: chain works
VERDICT_GATED = "gated"     # IP gate (403/426): long reputation cooldown
VERDICT_DEAD = "dead"       # 5xx / transport: short cooldown
_PROVEN = frozenset({VERDICT_SERVES, VERDICT_BUSY, VERDICT_STALE})


def normalize_verdict(result) -> str:
    """Probe result -> verdict string (bools keep legacy semantics)."""
    if result is True:
        return VERDICT_SERVES
    if result is False or result is None:
        return VERDICT_DEAD
    v = str(result).strip().lower()
    return v if v in (VERDICT_SERVES, VERDICT_BUSY, VERDICT_STALE,
                      VERDICT_GATED, VERDICT_DEAD) else VERDICT_SERVES


@dataclass
class StageFailure:
    """A stage-tagged chain failure recorded by a pin's forwarder."""

    stage: str   # entry | exit | target
    kind: str    # conn | http | proto
    at: float    # time.monotonic()


@dataclass
class Pin:
    """One egress: a loopback listener before an exit.

    Identity is (account, purpose, scope): ``scope`` "" pins the ACCOUNT
    (auth flows, catalogs -- never reaped); a non-empty scope pins one
    session.  ``quarantine_scope`` is the opaque app failure-domain key
    (provider name) this pin was created under, so a later quarantine can
    sweep exactly the pins that share its domain.
    """

    account: str
    purpose: str            # api | auth
    scope: str              # "" (account pin) | opaque session scope
    tags: tuple[str, ...]   # the account's list (the match selector)
    exit_url: str
    hops: int               # 1 without an entry, 2 with
    listener: ChainListener
    quarantine_scope: str = ""
    created: float = field(default_factory=time.time)

    @property
    def listener_url(self) -> str:
        return self.listener.url


class _KeyedMap(dict):
    """dict keyed by (account, purpose, scope) that accepts the legacy
    2-tuple (scope-less) form on every LOOKUP, normalizing it to scope "".

    Keeps pre-session call sites and tests addressing (account, purpose)
    working while the stored keys stay 3-tuples. Inserts must use the full
    3-tuple (internal code always does).
    """

    @staticmethod
    def _k(key):
        if isinstance(key, tuple) and len(key) == 2:
            return (key[0], key[1], "")
        return key

    def __getitem__(self, key):
        return super().__getitem__(self._k(key))

    def __contains__(self, key):
        return super().__contains__(self._k(key))

    def get(self, key, default=None):
        return super().get(self._k(key), default)

    def pop(self, key, *default):
        return super().pop(self._k(key), *default)

    def setdefault(self, key, default=None):
        return super().setdefault(self._k(key), default)


class QuarantineStore:
    """(opaque scope, exit url) -> expiry, TTL-bounded.

    The scope is whatever the application calls a failure domain (e.g. a
    provider type): Zen's gate-403 exit is poisoned only for that provider's
    pins, everything else keeps using it.  Expired entries are pruned lazily.
    """

    def __init__(self, ttl_seconds: int = 600):
        self.ttl = max(1, int(ttl_seconds or 600))
        self._until: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _now(now: float | None) -> float:
        return time.monotonic() if now is None else now

    def mark(self, scope: str, exit_url: str, *, ttl: float | None = None,
             now: float | None = None) -> float:
        """Quarantine `exit_url` for `scope`; returns the expiry.

        ``ttl`` overrides the store default per entry (verdict-cooldown
        split: gated hours / dead minutes); a re-mark with a SHORTER ttl
        never shortens an existing longer cooldown (min wins by keeping the
        later expiry)."""
        if not scope or not exit_url:
            return 0.0
        expires = self._now(now) + (self.ttl if ttl is None else max(1.0, float(ttl)))
        with self._lock:
            until = self._until.get((scope, exit_url))
            if until is not None and until > expires:
                return until  # an active longer cooldown stays put
        with self._lock:
            self._until[(scope, exit_url)] = expires
        return expires

    def active(self, scope: str, exit_url: str, *, now: float | None = None) -> bool:
        if not scope:
            return False
        now = self._now(now)
        with self._lock:
            until = self._until.get((scope, exit_url))
            if until is None:
                return False
            if until <= now:
                del self._until[(scope, exit_url)]
                return False
            return True

    def expiry(self, scope: str, exit_url: str, *, now: float | None = None) -> float | None:
        """Remaining seconds until expiry (None = not quarantined)."""
        if not scope:
            return None
        now = self._now(now)
        with self._lock:
            until = self._until.get((scope, exit_url))
            if until is None or until <= now:
                return None
            return until - now

    def entries(self, *, now: float | None = None) -> list[tuple[str, str, float]]:
        """Active (scope, exit_url, remaining seconds); expired ones pruned."""
        now = self._now(now)
        with self._lock:
            out = []
            for key, until in list(self._until.items()):
                if until <= now:
                    del self._until[key]
                else:
                    out.append((key[0], key[1], until - now))
        return sorted(out)

    def clear(self) -> None:
        with self._lock:
            self._until.clear()
@dataclass
class ChainsConfig:
    """Configuration for :class:`ProxyChains` (application-agnostic).

    path / refresh   local checker export + reload throttle.
    url / fetch      optional export SOURCE: re-downloaded at most every
                     ``fetch`` seconds (startup included), atomic write,
                     byte-compare, last-good on failure.  Requires ``path``
                     (it is the local cache file).
    entry_env        NAME of the env var holding the entry proxy URL (the
                     entry secret comes via env only -- never logged).
    quarantine_seconds  TTL for a quarantined (scope, exit).
    session_ttl      idle seconds after which a SESSION pin is reaped
                     (account pins are never reaped).
    max_session_pins cap on session pins per account (LRU eviction).
    preflight_ttl    seconds a preflight-validated exit stays WARM (and the
                     minimum spacing between preflight sweeps per account).
    cooldown_gated_seconds  TTL for an IP-GATE verdict (403/426): a
                     reputation verdict outlives transport noise by hours.
    cooldown_dead_seconds   TTL for a DEAD verdict (5xx/transport).
    cooldown_rate_seconds   TTL for an exit quarantined on a live 429.
    bind_host        listener bind address (default 127.0.0.1 = unchanged).
                     A wildcard ("0.0.0.0") exposes listeners on the LAN and
                     REQUIRES bind_user + bind_pass (refused otherwise).
    bind_user/bind_pass  Basic credentials clients must present (also kept
                     as URL userinfo for httpx/curl/Chromium).  Unset = no
                     gate -- exactly the previous loopback behavior.
    advertise_host   host embedded in handed-out listener URLs when
                     bind_host is a wildcard (default: bind_host).
    """

    path: str = ""
    refresh: int = 60
    url: str = ""
    fetch: int = 3600
    entry_env: str = "PROXIES_ENTRY"
    quarantine_seconds: int = 600
    session_ttl: int = 900
    max_session_pins: int = 32
    preflight_ttl: int = 300
    cooldown_gated_seconds: int = 21600
    cooldown_dead_seconds: int = 600
    cooldown_rate_seconds: int = 300
    bind_host: str = "127.0.0.1"
    advertise_host: str = ""
    bind_user: str = ""
    bind_pass: str = ""


class ProxyChains:
    """Pins, rotation, quarantine and redacted status for tag-based egress.

    Pin identity: ``(account, purpose, scope)``.  ``scope`` "" = the account
    pin (auth flows, catalogs -- never reaped); a non-empty scope (the
    application's session id) gets ITS OWN pin, so concurrent sessions spread
    across exits instead of sharing one IP.  New exits are chosen at RANDOM
    from the free matches (the pool list is IP-sorted -- never pick its head).

    Failure domains: callers tag pins with an OPAQUE ``quarantine_scope``
    (provider name, ...).  When a failure rule declares an exit bad for that
    domain (``FailurePlan.quarantine_scope``), ``rotate(quarantine_scope=)``
    marks the exit for ``cfg.quarantine_seconds`` AND sweeps every pin of the
    same domain off it in one pass; ``egress()``/``rotate()`` then exclude
    quarantined exits -- and when the WHOLE matching set is quarantined they
    probe the least-recently-quarantined one instead of failing (never a
    setup error: the pool matched, every candidate is just poisoned).

    Application seam (why this package stays reusable): ``tags_for`` returns
    the raw tag/URL list for (account, purpose) -- raising the app's setup
    error for unknown accounts; ``explicit_for`` returns an explicit proxy
    override (it wins over tags); ``setup_error`` is the exception class
    raised on a tag miss.  Quarantine keys and scopes are opaque strings.
    This module never imports application config.
    """

    def __init__(self, cfg: ChainsConfig, *,
                 setup_error: type[Exception] = ProxySetupError,
                 tags_for: Callable[[str, str], Sequence] | None = None,
                 explicit_for: Callable[[str, str, "str | None"], "str | None"] | None = None):
        self._cfg = cfg
        self._entry_env = (cfg.entry_env or "").strip() or "PROXIES_ENTRY"
        self._pool = ChainPool(cfg.path, cfg.refresh, url=cfg.url, fetch=cfg.fetch)
        self._lock = threading.Lock()
        self._pins: _KeyedMap = _KeyedMap()
        self._failures: _KeyedMap = _KeyedMap()
        self._quarantine = QuarantineStore(cfg.quarantine_seconds)
        # Preflight warm set: (quarantine scope -> exit url -> validated-at).
        # Only exits that ANSWERED a real probe (via a throwaway listener, so
        # the probe exercised the same hops as live traffic) are preferred by
        # _pick; a warm entry older than preflight_ttl simply stops counting.
        self._warm: dict[str, dict[str, float]] = {}
        # Persistent "WORKS" overlay: (quarantine scope -> exit url ->
        # verified-at).  Unlike _warm it has NO TTL -- an exit stays tagged as
        # working until a LATER probe proves it dead (then it is dropped and
        # quarantined).  A full-pool sweep (preflight(full=True)) fills this
        # with every exit that truly serves, so tag/status can show which of
        # the ~262 candidates actually work even after warm expiry / restart.
        self._works: dict[str, dict[str, float]] = {}
        self._warm_lock = threading.Lock()  # guards BOTH _warm and _works
        # First-seen monotonic per exit URL: drives the preflight QUEUE order
        # (newest pool arrivals are probed first) and the overlay prune.
        self._seen: dict[str, float] = {}
        # Preflight progress per qscope (counts only -- panel renders queue
        # size / running state, never exit lists).
        self._pf: dict[str, dict] = {}
        self._pf_lock = threading.Lock()
        self._setup_error = setup_error
        self._tags_for = tags_for
        self._explicit_for = explicit_for
        # Bind policy: loopback by default (unchanged behavior); a wildcard
        # bind pairs with credentials (refused without them), and
        # advertise_host overrides the host clients are told to dial.
        self._bind_host = (cfg.bind_host or "").strip() or "127.0.0.1"
        self._advertise_host = ((cfg.advertise_host or "").strip()
                                or self._bind_host)
        self._bind_user = (cfg.bind_user or "").strip()
        self._bind_pass = cfg.bind_pass or ""
        self._bind_auth = (_basic_auth(self._bind_user, self._bind_pass)
                           if self._bind_user else None)
        if (self._bind_host not in ("127.0.0.1", "::1", "localhost")
                and not (self._bind_user and self._bind_pass)):
            raise ProxySetupError(
                503, "bind_host outside loopback requires bind_user + bind_pass")

    @property
    def pool(self) -> ChainPool:
        return self._pool

    # -- entry (secret via env only: never YAML, never logged, never status)
    @property
    def entry_env(self) -> str:
        return self._entry_env

    @property
    def entry_configured(self) -> bool:
        return bool(os.environ.get(self._entry_env, "").strip())

    def _entry(self) -> Proxy | None:
        raw = os.environ.get(self._entry_env, "").strip()
        return Proxy(raw) if raw else None
    # -- resolution ----------------------------------------------------------
    def egress(self, account: str, purpose: str = "api", *,
               model: str | None = None, scope: str = "",
               quarantine_scope: str = "") -> str | None:
        """Proxy URL httpx should use for this (account, purpose[, scope]);
        None = direct.

        Precedence: explicit override (the app's ``explicit_for`` hook --
        api_proxy/auth_proxy/model_proxies) > a URL item in the tag list
        (used as-is: hop 1, bypasses the entry) > tag pins (pinned loopback
        listener: 2 hops with an entry, 1 without).  ``scope`` "" addresses
        the account pin; a session scope gets a per-session pin (reaped after
        ``cfg.session_ttl`` idle, capped at ``cfg.max_session_pins``).
        """
        tags: Sequence = ()
        if self._tags_for is not None:
            tags = self._tags_for(account, purpose)  # raises for unknown accounts
        if self._explicit_for is not None:
            explicit = self._explicit_for(account, purpose, model)
            if explicit:
                return explicit
        if not tags:
            return None
        for raw in tags:
            item = str(raw).strip()
            if "://" in item:  # direct URL: hop 1, always bypasses the entry
                return item
        selected = tuple(str(t).strip() for t in tags if str(t).strip())
        scope_key = scope or ""
        key = (account, purpose, scope_key)
        to_close: list[ChainListener] = []
        try:
            self._maintain(account, to_close)
            with self._lock:
                pin = self._pins.get(key)
                if pin is not None and quarantine_scope and not pin.quarantine_scope:
                    pin.quarantine_scope = quarantine_scope  # adopt caller's key
            if pin is not None:
                qscope = pin.quarantine_scope or quarantine_scope
                if qscope and self._quarantine.active(qscope, pin.exit_url):
                    # the exit was quarantined under our domain (sweep could not
                    # move us: no free alternative back then) -- heal now.
                    pin = self._repin(key, pin, qscope, to_close) or pin
                return pin.listener_url
            return self._create_pin(
                account, purpose, scope_key, selected, quarantine_scope,
                to_close,
            ).listener_url
        finally:
            for listener in to_close:
                listener.close()

    # -- preflight: prove exits serve the provider BEFORE pinning ----------
    def _warm_urls(self, qscope: str = "", now: float | None = None) -> set[str]:
        """Exit URLs freshly preflight-validated for this domain (raw URLs)."""
        now = time.monotonic() if now is None else now
        ttl = max(1, int(self._cfg.preflight_ttl or 300))
        with self._warm_lock:
            scope_map = self._warm.get(qscope) or {}
            return {u for u, at in scope_map.items() if now - at <= ttl}

    def _warm_mark(self, qscope: str, url: str) -> None:
        with self._warm_lock:
            self._warm.setdefault(qscope, {})[url] = time.monotonic()

    def _warm_drop(self, qscope: str, url: str) -> None:
        with self._warm_lock:
            self._warm.get(qscope, {}).pop(url, None)

    def _works_set(self, qscope: str) -> set[str]:
        with self._warm_lock:
            return set(self._works.get(qscope) or {})

    def _works_mark(self, qscope: str, url: str) -> None:
        with self._warm_lock:
            self._works.setdefault(qscope, {})[url] = time.monotonic()

    def _works_drop(self, qscope: str, url: str) -> None:
        with self._warm_lock:
            self._works.get(qscope, {}).pop(url, None)

    def _cooldown_ttl(self, verdict: str) -> float:
        """Per-verdict quarantine TTL (0 = store default)."""
        if verdict == VERDICT_GATED:
            return float(self._cfg.cooldown_gated_seconds or 21600)
        if verdict == VERDICT_DEAD:
            return float(self._cfg.cooldown_dead_seconds or 600)
        return 0.0

    def _prune_overlays(self) -> None:
        """Drop warm/works/seen entries for exits the pool no longer serves.

        The checker export is the membership authority: an exit that left
        the refresh can never be re-probed, so without this prune it would
        stay tagged "works" (or linger in the dicts) forever."""
        try:
            pool_urls = self._pool.urls()
        except Exception:  # noqa: BLE001 - a broken pool must not sink callers
            return
        with self._warm_lock:
            scopes = set(self._warm) | set(self._works)
            dropped = 0
            for scope in scopes:
                for mapping in (self._warm.get(scope), self._works.get(scope)):
                    if not mapping:
                        continue
                    for url in [u for u in mapping if u not in pool_urls]:
                        del mapping[url]
                        dropped += 1
            for url in [u for u in self._seen if u not in pool_urls]:
                del self._seen[url]
        if dropped:
            log.info("proxy overlays pruned: %d stale entr(y/ies) "
                     "(exit left the refresh)", dropped)

    async def preflight(self, account: str, purpose: str,
                        probe: Callable[[str], Awaitable[bool]], *,
                        qscope: str = "", limit: int = 6,
                        concurrency: int = 4, full: bool = False,
                        timeout: float = _PREFLIGHT_TIMEOUT) -> list[str]:
        """Probe up to ``limit`` tag-matched candidates and warm the ones
        that answer; returns the RAW warm exit URLs for this domain.

        ``full=True`` sweeps EVERY not-yet-proven, not-quarantined candidate
        (ignores ``limit``) -- the whole-pool fine check (a caller passes a
        higher ``concurrency`` for a large pool).  Every exit that answers is
        tagged into the persistent WORKS overlay in addition to the warm set.

        ``probe(url)`` is an application coroutine receiving the loopback
        listener URL of ONE candidate chain ([entry ->] exit -> target) --
        it runs over exactly the hops live traffic will use, so a proxy
        this VDI cannot reach (or an entry hop that refuses it) fails here
        instead of burning a request later.  Return True when the candidate
        serves the application's provider; timeouts and exceptions count as
        failures.

        A success WARM-marks the exit for ``qscope`` (an opaque app domain
        key, e.g. the provider name) until ``cfg.preflight_ttl`` elapses --
        every later pin/rotation prefers warm exits (see ``_pick``).  A
        failure drops the exit from the warm set and QUARANTINES it for the
        domain, so pins never land on an exit we just measured as dead.
        Explicit egress, direct-URL tags and tag misses are a no-op (return
        the current warm set) -- nothing here can pin or fail a request.
        """
        qscope = qscope or ""
        tags: Sequence = ()
        if self._tags_for is not None:
            tags = self._tags_for(account, purpose)  # raises for unknown accounts
        if self._explicit_for is not None and self._explicit_for(account, purpose,
                                                                 None):
            return sorted(self._warm_urls(qscope))
        if not tags:
            return []
        for raw in tags:
            if "://" in str(raw).strip():  # direct URL: no pool exit to probe
                return []
        selected = tuple(str(t).strip() for t in tags if str(t).strip())
        self._prune_overlays()
        hits = self._pool.matches(selected)
        if not hits:
            return []
        now = time.monotonic()
        # First-seen registry: pool order is the fallback, so an exit that
        # just arrived in the refresh sorts NEWEST and probes first.
        with self._warm_lock:
            for h in hits:
                self._seen.setdefault(h.url, now)
        warm = self._warm_urls(qscope, now)
        pinned = {p.exit_url for (_a, _p, _s), p in list(self._pins.items())}
        works = self._works_set(qscope)
        # The QUEUE: not-warm, not-pinned, not cooling.  FIFO order: NEVER-
        # proven pool arrivals first (newest first -- a fresh refresh entry
        # is probed before a long-lived unverified one), then works entries
        # whose warm TTL lapsed (re-validation, cheap and last).  Successful
        # probes warm immediately, so each hit is pickable at once.
        cold = [h for h in hits if h.url not in warm and h.url not in pinned
                and not self._quarantine.active(qscope, h.url, now=now)]
        cold.sort(key=lambda h: (h.url in works, -self._seen.get(h.url, 0.0)))
        # full=True sweeps the WHOLE queue (fine check); otherwise a bounded
        # slice (the periodic sweep, preflight_limit per pass).
        batch = cold if full else cold[: max(0, int(limit))]
        progress = {"running": False, "account": account,
                    "queue": len(cold), "total": 0, "done": 0, "ok": 0}
        with self._pf_lock:
            self._pf[qscope] = progress
        if batch:
            progress.update(running=True, total=len(batch))
            sem = asyncio.Semaphore(max(1, int(concurrency)))
            entry = self._entry()

            async def _one(pentry: PoolEntry) -> str:
                async with sem:
                    listener = self._spawn(
                        entry, Proxy(pentry.url), (account, purpose, "preflight"))
                    try:
                        verdict = normalize_verdict(
                            await asyncio.wait_for(probe(listener.url), timeout))
                    except Exception:  # noqa: BLE001 - dead/slow = failed probe
                        verdict = VERDICT_DEAD
                    finally:
                        listener.close()
                    if verdict in _PROVEN:
                        # Immediate promotion: the exit is pickable by the
                        # NEXT pin/rotation, not when the sweep finishes.
                        self._warm_mark(qscope, pentry.url)
                        self._works_mark(qscope, pentry.url)
                        log.info("proxy preflight %s: %s %s (warm+works)",
                                 account, masked_url(pentry.url), verdict)
                    else:
                        self._warm_drop(qscope, pentry.url)
                        self._works_drop(qscope, pentry.url)
                        if qscope:
                            self._quarantine.mark(qscope, pentry.url,
                                                  ttl=self._cooldown_ttl(verdict))
                        log.warning(
                            "proxy preflight %s: %s %s -> quarantined",
                            account, masked_url(pentry.url), verdict)
                    progress["done"] += 1
                    if verdict in _PROVEN:
                        progress["ok"] += 1
                    return verdict

            try:
                await asyncio.gather(*(_one(h) for h in batch))
            finally:
                progress["running"] = False
        return sorted(self._warm_urls(qscope))

    def _maintain(self, account: str, to_close: list) -> None:
        """Opportunistic upkeep (under the pin lock): reap idle SESSION pins
        past ``cfg.session_ttl`` (account pins -- scope "" -- never reap) and
        evict this account's least-recently-used session pins beyond
        ``cfg.max_session_pins`` (graceful cap; account pins never count)."""
        ttl = int(self._cfg.session_ttl or 0)
        cap = int(self._cfg.max_session_pins or 0)
        now = time.time()
        with self._lock:
            if ttl > 0:
                for key, pin in list(self._pins.items()):
                    if key[2] and now - pin.listener.last_used > ttl:
                        self._pins.pop(key, None)
                        self._failures.pop(key, None)
                        to_close.append(pin.listener)
                        log.debug("proxy pin reaped (idle > %ds) %s/%s[%s]",
                                  ttl, key[0], key[1], key[2])
            if cap > 0:
                mine = sorted(
                    ((k, p) for k, p in self._pins.items()
                     if k[0] == account and k[2]),
                    key=lambda kv: kv[1].listener.last_used,
                )
                while len(mine) >= cap:
                    key, pin = mine.pop(0)  # least recently used
                    self._pins.pop(key, None)
                    self._failures.pop(key, None)
                    to_close.append(pin.listener)
                    log.debug("proxy pin cap reached (%d) -- evicted %s/%s[%s]",
                              cap, key[0], key[1], key[2])
    def _create_pin(self, account: str, purpose: str, scope: str,
                    tags: tuple[str, ...], quarantine_scope: str,
                    to_close: list) -> Pin:
        """Fresh pin for a never-seen key: random free exit, fail-fast miss."""
        entry = self._entry()
        chosen = self._pick(tags, qscope=quarantine_scope)
        if chosen is None:
            raise self._setup_error(
                503,
                f"no proxy matches tags {list(tags)} "
                f"({self._pool.count} entries loaded)")
        key = (account, purpose, scope)
        listener = self._spawn(entry, Proxy(chosen.url), key)
        pin = Pin(account=account, purpose=purpose, scope=scope, tags=tags,
                  exit_url=chosen.url, hops=2 if entry else 1,
                  listener=listener, quarantine_scope=quarantine_scope or "")
        with self._lock:
            existing = self._pins.get(key)
            if existing is not None:  # lost a race: keep the first pin
                to_close.append(listener)
                return existing
            self._pins[key] = pin
        log.debug("proxy pin %s/%s[%s] -> %s (hops=%d)", account, purpose,
                  scope or "-", masked_url(pin.exit_url), pin.hops)
        return pin

    def _pick(self, tags: tuple[str, ...], *, exclude: str | None = None,
              qscope: str = "", warm_only: bool = False) -> PoolEntry | None:
        """Random matching exit honoring the quarantine.

        Free (not-quarantined-for-``qscope``) candidates first; ``exclude``
        prefers a different exit (rotation); when EVERY candidate is
        quarantined, probe the LEAST-RECENTLY-quarantined one (the one whose
        TTL expires soonest) instead of returning None -- the pool matched,
        every candidate is just poisoned, and failing here would surface a
        config error for what is a transient network gate.

        ``warm_only`` restricts candidates to PREFLIGHT-PROVEN exits
        (works/warm, TTL-expired warm still counts via works) and returns
        None when there is none -- used by the 429 rate rotation so a retry
        never burns a cold candidate.
        """
        hits = self._pool.matches(tags)
        if not hits:
            return None
        now = time.monotonic()
        if warm_only:
            works = self._works_set(qscope)
            warm = self._warm_urls(qscope, now)
            proven = [h for h in hits if h.url in works or h.url in warm]
            if not proven:
                return None
            hits = proven
        if qscope:
            free = [h for h in hits
                    if not self._quarantine.active(qscope, h.url, now=now)]
            if free:
                hits = free
            else:
                # all quarantined: least-recently-quarantined = soonest to expire
                hits = sorted(
                    hits,
                    key=lambda h: self._quarantine.expiry(qscope, h.url, now=now)
                    or 0.0,
                )
        # Preflight preference: exits that recently PROVED they serve this
        # domain (see preflight()) rank above never-probed ones.  The
        # persistent WORKS overlay wins first (survives warm TTL until a
        # later probe disproves it), then the short-TTL warm set.  With no
        # proven exits the pool behaves exactly as before.
        works = self._works_set(qscope)
        warm = self._warm_urls(qscope, now)
        preferred = [h for h in hits if h.url in works] if works else []
        if not preferred and warm:
            preferred = [h for h in hits if h.url in warm]
        if preferred:
            hits = preferred
        if exclude is not None:
            rest = [h for h in hits if h.url != exclude]
            if rest:
                hits = rest
        return random.choice(hits)

    def _spawn(self, entry: Proxy | None, exitp: Proxy,
               key: tuple[str, ...]) -> ChainListener:
        """Bind a fresh listener for one chain (ephemeral port, bind policy)."""
        server = _Server((self._bind_host, 0), _Handler)
        creds = ""
        if self._bind_user:
            creds = (urllib.parse.quote(self._bind_user, safe="") + ":"
                     + urllib.parse.quote(self._bind_pass, safe="") + "@")
        listener = ChainListener(
            entry=entry,
            exit=exitp,
            url=f"http://{creds}{self._advertise_host}:{server.server_address[1]}",
            server=server,
            thread=None,
            last_used=time.time(),
            on_failure=lambda stage, kind, k=key: self._record(k, stage, kind),
            auth=self._bind_auth,
        )
        server.listener = listener
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.2},
                                  name=f"chain-{server.server_address[1]}",
                                  daemon=True)
        listener.thread = thread
        thread.start()
        return listener
    def _repin(self, key: tuple[str, str, str], old: Pin, qscope: str,
               to_close: list) -> Pin | None:
        """Move a pin whose exit is quarantined for our domain onto a free
        exit.  Returns the pin to USE (the fresh one, or -- when no free
        alternative exists -- the caller's old pin, i.e. no move).  Pick and
        spawn happen outside the pin lock; the swap is race-guarded."""
        chosen = self._pick(old.tags, exclude=old.exit_url, qscope=qscope)
        if chosen is None or chosen.url == old.exit_url:
            return None
        return self._swap(key, old, chosen, qscope, to_close)

    def _swap(self, key: tuple[str, str, str], old: Pin, chosen: PoolEntry,
              qscope: str, to_close: list) -> Pin | None:
        """Replace `old` at `key` with a listener on `chosen` (race-guarded:
        the first writer wins; a loser returns the winner's pin)."""
        entry = self._entry()
        listener = self._spawn(entry, Proxy(chosen.url), key)
        fresh = Pin(account=key[0], purpose=key[1], scope=key[2],
                    tags=old.tags, exit_url=chosen.url,
                    hops=2 if entry else 1, listener=listener,
                    quarantine_scope=qscope or old.quarantine_scope)
        with self._lock:
            current = self._pins.get(key)
            if current is not old:
                to_close.append(listener)
                return current  # someone else already moved it: keep theirs
            self._pins[key] = fresh
            self._failures.pop(key, None)  # the record belonged to the dead exit
        to_close.append(old.listener)
        log.info("proxy pin %s/%s[%s] -> %s (hops=%d)", key[0], key[1],
                 key[2] or "-", masked_url(fresh.exit_url), fresh.hops)
        return fresh

    def _sweep(self, qscope: str, exit_url: str, *, skip: tuple[str, str, str],
               to_close: list) -> int:
        """Move EVERY other pin of this quarantine domain off `exit_url` in
        one pass.  Pins without a free alternative stay put; egress() heals
        them later once an alternative exists (or the TTL lapses)."""
        with self._lock:
            victims = [(k, p) for k, p in self._pins.items()
                       if k != skip and p.exit_url == exit_url
                       and p.quarantine_scope == qscope]
        moved = 0
        for key, pin in victims:
            chosen = self._pick(pin.tags, exclude=exit_url, qscope=qscope)
            if chosen is None or chosen.url == exit_url:
                continue
            if self._swap(key, pin, chosen, qscope, to_close) is not None:
                moved += 1
        if moved:
            log.info("proxy quarantine sweep %s: moved %d pin(s) off %s",
                     qscope, moved, masked_url(exit_url))
        return moved

    def quarantine(self, qscope: str, exit_url: str, *,
                   cooldown_seconds: float = 0.0) -> None:
        """Mark `exit_url` quarantined for the opaque domain `qscope` only
        (no sweep -- use rotate(quarantine_scope=...) for mark + sweep +
        re-pin in one step).  ``cooldown_seconds`` overrides the default
        TTL per verdict class."""
        self._quarantine.mark(qscope, exit_url,
                              ttl=cooldown_seconds or None)
        self._warm_drop(qscope, exit_url)  # a poisoned exit is no longer warm

    def rotate(self, account: str, purpose: str = "api", *,
               scope: str = "", quarantine_scope: str | None = None,
               cooldown_seconds: float = 0.0,
               warm_only: bool = False) -> bool:
        """Pin a DIFFERENT exit for (account, purpose[, scope]).

        Returns False when there is nothing to rotate (no pin -- direct or
        explicit egress -- or the pool has no free alternative); the caller
        must then surface the failure instead of retrying.

        ``quarantine_scope``: also MARK the current exit quarantined under
        this opaque domain key (TTL = cfg.quarantine_seconds unless
        ``cooldown_seconds`` overrides it) and sweep every sibling pin of the
        same domain off it before picking the fresh exit.  ``warm_only``:
        pick among preflight-proven exits only (False = no alternates
        available, surface instead of burning a cold candidate).
        """
        key = (account, purpose, scope or "")
        with self._lock:
            old = self._pins.get(key)
        if old is None:
            return False
        qscope = quarantine_scope or ""
        to_close: list[ChainListener] = []
        try:
            if qscope:
                self._quarantine.mark(qscope, old.exit_url,
                                      ttl=cooldown_seconds or None)
                self._warm_drop(qscope, old.exit_url)  # poisoned: no longer warm
                if not old.quarantine_scope:
                    with self._lock:
                        old.quarantine_scope = qscope  # future sweeps find it
                self._sweep(qscope, old.exit_url, skip=key, to_close=to_close)
            chosen = self._pick(
                old.tags, exclude=old.exit_url,
                qscope=qscope or old.quarantine_scope, warm_only=warm_only,
            )
            if chosen is None or chosen.url == old.exit_url:
                log.warning("proxy rotate: no alternate exit for tags %s (%d loaded)",
                            list(old.tags), self._pool.count)
                return False
            fresh = self._swap(key, old, chosen,
                               qscope or old.quarantine_scope, to_close)
            return fresh is not None and fresh.exit_url != old.exit_url
        finally:
            for listener in to_close:
                listener.close()
    # -- failure attribution -------------------------------------------------
    def _record(self, key: tuple, stage: str, kind: str) -> None:
        if isinstance(key, tuple) and len(key) == 2:
            key = (key[0], key[1], "")
        with self._lock:
            self._failures[key] = StageFailure(stage=stage, kind=kind,
                                               at=time.monotonic())

    def stage_action(self, account: str, purpose: str,
                     scope: str = "") -> tuple[str, str, str]:
        """Fresh chain failure for this pin as (action, stage, kind):
        ('entry', ...) = the entry's fault -- surface, do not burn exits;
        ('exit', ...)  = exit-dead -- rotate;
        ('', '', '')   = nothing fresh to attribute.

        entry/proto maps to 'exit': a squid-like entry closes the connection
        when ITS dial to the exit fails instead of returning 502, so only
        entry/conn and entry/http(407) are the entry's own fault.
        """
        key = (account, purpose, scope or "")
        with self._lock:
            fail = self._failures.get(key)
        if fail is None or time.monotonic() - fail.at > _STAGE_FRESH_SECONDS:
            return "", "", ""
        if fail.stage == "entry" and fail.kind != "proto":
            return "entry", fail.stage, fail.kind
        return "exit", fail.stage, fail.kind

    # -- observability --------------------------------------------------------
    def status(self) -> dict:
        """Redacted observability block: pool source/size/age, pin counts BY
        SCOPE, per-exit pin/session counts (MASKED exits, no session
        identifiers, no entry value -- presence only)."""
        with self._lock:
            pins = dict(self._pins)
        by_scope = {"account": 0, "session": 0}
        exits: dict[str, dict] = {}
        for (account, _purpose, scope), pin in sorted(pins.items()):
            by_scope["session" if scope else "account"] += 1
            masked = masked_url(pin.exit_url)
            slot = exits.setdefault(masked,
                                    {"pins": 0, "sessions": 0, "accounts": 0})
            slot["pins"] += 1
            if scope:
                slot["sessions"] += 1
            slot["accounts"] = len({a for (a, _p, _s), p in pins.items()
                                    if masked_url(p.exit_url) == masked})
        quarantined = [
            {"scope": scope, "exit": masked_url(url),
             "expires_in": round(remaining, 1)}
            for scope, url, remaining in self._quarantine.entries()
        ]
        # preflight warm/works COUNTS per scope. Counts only -- the panel just
        # needs how many exits are warm/verified, never the exit list.
        self._prune_overlays()
        ttl = max(1, int(self._cfg.preflight_ttl or 300))
        now = time.monotonic()
        with self._warm_lock:
            warm_scopes = {
                scope: sum(1 for at in exits.values() if now - at <= ttl)
                for scope, exits in self._warm.items()
            }
            # persistent works (no TTL): every exit proven to serve, until a
            # later probe disproves it.
            works_scopes = {
                scope: len(exits) for scope, exits in self._works.items()
            }
        return {
            "enabled": bool(self._pool.path or self._pool.url),
            "path": self._pool.path,
            "url": self._pool.url,
            "fetch": int(self._cfg.fetch or 0),
            "refresh": self._pool.refresh,
            "entry": self.entry_configured,   # presence only, never the value
            "entry_env": self._entry_env,
            "loaded": self._pool.count,
            "tag_counts": self._pool.tag_counts,
            "next_fetch_in": self._pool.next_fetch_in,
            "age_seconds": self._pool.age_seconds,
            "error": self._pool.last_error,
            "session_ttl": self._cfg.session_ttl,
            "max_session_pins": self._cfg.max_session_pins,
            "quarantine_seconds": self._cfg.quarantine_seconds,
            "cooldowns": {
                "gated": int(self._cfg.cooldown_gated_seconds or 21600),
                "dead": int(self._cfg.cooldown_dead_seconds or 600),
                "rate": int(self._cfg.cooldown_rate_seconds or 300),
            },
            "preflight_ttl": ttl,
            "preflight": {
                scope: {k: v for k, v in st.items() if k != "account"}
                for scope, st in sorted(self._pf_progress().items())
            },
            "warm": {scope: n for scope, n in sorted(warm_scopes.items()) if n},
            "works": {scope: n for scope, n in sorted(works_scopes.items())
                      if n},
            "pins": {
                "total": len(pins),
                "by_scope": by_scope,
                "exits": exits,
            },
            "quarantined": quarantined,
        }

    def _pf_progress(self) -> dict[str, dict]:
        """Snapshot of the per-scope preflight progress (counts only)."""
        with self._pf_lock:
            return {scope: dict(st) for scope, st in self._pf.items()}

    def close(self) -> None:
        """Shut every listener down (lifespan teardown)."""
        with self._lock:
            pins = list(self._pins.values())
            self._pins.clear()
            self._failures.clear()
        self._quarantine.clear()
        with self._warm_lock:
            self._warm.clear()
            self._works.clear()
        for pin in pins:
            pin.listener.close()





