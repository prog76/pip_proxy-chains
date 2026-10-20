"""Pool -- the proxychecker export, loadable from a file OR a URL."""

from __future__ import annotations

import json
import logging
import os
import random
import threading
import time
import urllib.request
from dataclasses import dataclass
from typing import Iterable

from .plans import SUPPORTED_SCHEMES

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class PoolEntry:
    url: str
    tags: frozenset[str]


class ChainPool:
    """Checker export loader (``proxies.path``), optionally refreshed from
    ``proxies.url``.

    Reload at most once per ``refresh`` seconds when mtime/size changed; a
    missing, invalid or empty export keeps the last-good entries -- the pool
    never empties once loaded.  Selection is AND-match (chains/loader.py
    semantics): an entry qualifies when it carries every requested tag.
    A "-"-prefixed request tag negates: an entry that carries "-x" is
    never returned for a request containing "x".  Schemes outside
    plans.SUPPORTED_SCHEMES are dropped at load (undialable from here).

    URL source: when ``url`` is set, the export is re-downloaded at most once
    per ``fetch`` seconds (first attempt at startup), byte-compared against
    the local file (identical content touches nothing), then written ATOMICALLY
    (tmp file + os.replace in the same directory).  Any fetch failure keeps
    the on-disk file -- which keeps the last-good pool -- and is reported via
    ``last_error`` without disturbing a healthy pool.
    """

    def __init__(self, path: str, refresh: int = 60, *,
                 url: str = "", fetch: int = 3600, fetch_timeout: float = 20):
        self.path = (path or "").strip()
        self.refresh = max(1, int(refresh or 60))
        self.url = (url or "").strip()
        self.fetch_interval = max(0, int(fetch or 3600))
        self.fetch_timeout = fetch_timeout
        self._lock = threading.Lock()
        self._entries: tuple[PoolEntry, ...] = ()
        self._stamp: tuple[float, int] | None = None
        self._loaded_at: float = 0.0   # wall clock of the last good load
        self._checked_at: float = 0.0  # monotonic of the last reload attempt
        self._last_fetch: float = 0.0  # monotonic of the last fetch attempt
        self._parse_error: str | None = None
        self._fetch_error: str | None = None
        if self.path:
            if self.url:
                self._fetch(force=True)  # startup fetch: best-effort, then load
            self.reload(force=True)

    # -- URL source (design A) --------------------------------------------
    def _fetch(self, force: bool = False) -> bool:
        """Download the export to ``path``; True when the file was replaced.

        Throttled by ``fetch`` seconds (``force`` = startup), byte-compared
        against the current file (no-op write when unchanged), atomic replace.
        On ANY failure the old file stays and ``_fetch_error`` is recorded --
        last-good semantics mirror the parse path.
        """
        if not self.url or not self.path:
            return False
        now = time.monotonic()
        if not force:
            if self.fetch_interval <= 0:
                return False
            if now - self._last_fetch < self.fetch_interval:
                return False
        self._last_fetch = now  # set even on failure: don't hammer a dead URL
        try:
            with urllib.request.urlopen(self.url, timeout=self.fetch_timeout) as resp:
                data = resp.read()
        except Exception as e:  # noqa: BLE001 - any fetch fault keeps last-good
            self._fetch_error = f"fetch failed: {e}"
            log.warning("proxy export fetch failed -- keeping local file (%s)", e)
            return False
        try:
            with open(self.path, "rb") as fh:
                old = fh.read()
        except OSError:
            old = None
        if data == old:
            self._fetch_error = None  # fetched fine, nothing to do
            return False
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except OSError as e:
            self._fetch_error = f"fetch write failed: {e}"
            log.error("proxy export fetch write failed -- keeping last-good (%s)", e)
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False
        self._fetch_error = None
        log.info("proxy export fetched %d bytes -> %s", len(data), self.path)
        return True
    def _stat(self) -> tuple[float, int] | None:
        try:
            st = os.stat(self.path)
            return (st.st_mtime, st.st_size)
        except OSError:
            return None

    def reload(self, force: bool = False) -> bool:
        """Throttled mtime/interval reload; True when entries were replaced."""
        if not self.path:
            return False
        now = time.monotonic()
        with self._lock:
            if not force and now - self._checked_at < self.refresh:
                return False
            self._checked_at = now
            if self.url:
                self._fetch()  # throttled internally by fetch_interval
            stamp = self._stat()
            if not force and stamp == self._stamp:
                return False
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    raw = json.load(fh)
            except OSError as e:
                self._parse_error = f"cannot read export: {e.strerror or e}"
                log.error("proxy export unreadable -- keeping last-good (%d entries)",
                          len(self._entries))
                return False
            except ValueError as e:
                self._parse_error = f"invalid json: {e}"
                log.error("proxy export invalid -- keeping last-good (%d entries)",
                          len(self._entries))
                return False
            items = raw.get("proxies") if isinstance(raw, dict) else None
            if not isinstance(items, list):
                self._parse_error = "export has no proxies[] list"
                log.error("proxy export shape wrong -- keeping last-good (%d entries)",
                          len(self._entries))
                return False
            fresh: list[PoolEntry] = []
            skipped: dict[str, int] = {}
            for item in items:
                if not isinstance(item, dict):
                    continue
                proxy = item.get("proxy")
                if not isinstance(proxy, str) or ":" not in proxy:
                    continue
                scheme = str(item.get("scheme") or "http").strip() or "http"
                if scheme.lower() not in SUPPORTED_SCHEMES:
                    skipped[scheme] = skipped.get(scheme, 0) + 1
                    continue
                tags = item.get("tags") or []
                if not all(isinstance(t, str) for t in tags):
                    continue
                fresh.append(PoolEntry(f"{scheme}://{proxy.strip()}",
                                       frozenset(tags)))
            if not fresh and self._entries:
                # a truncated/emptied export must never wipe a live pool
                self._parse_error = "export parsed to 0 proxies"
                log.error("proxy export parsed to 0 proxies -- keeping last-good (%d entries)",
                          len(self._entries))
                return False
            self._entries = tuple(fresh)
            self._stamp = stamp
            self._loaded_at = time.time()
            self._parse_error = None
            log.info("proxy pool loaded %d entries", len(fresh))
            if skipped:
                log.warning("proxy scheme filter dropped %d entries: %s",
                            sum(skipped.values()),
                            ", ".join(f"{k}={v}" for k, v in sorted(skipped.items())))
            return True

    @property
    def count(self) -> int:
        self.reload()
        with self._lock:
            return len(self._entries)

    def urls(self) -> set[str]:
        """Every loaded exit URL (pool membership check for overlay prune)."""
        self.reload()
        with self._lock:
            return {e.url for e in self._entries}

    @property
    def tag_counts(self) -> dict[str, int]:
        """Histogram of tags across the pool (how many entries carry each
        tag). Lets the panel show "alive: N" without knowing tag names."""
        self.reload()
        with self._lock:
            entries = self._entries
        counts: dict[str, int] = {}
        for e in entries:
            for t in e.tags:
                counts[t] = counts.get(t, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    @property
    def next_fetch_in(self) -> float | None:
        """Seconds until the next URL fetch attempt (None = no URL source).
        0 = due right now (throttle window elapsed, runs on the next reload)."""
        if not self.url or self.fetch_interval <= 0:
            return None
        with self._lock:
            last = self._last_fetch
        if last <= 0.0:
            return 0.0  # never fetched (path was empty at construction)
        return round(max(0.0, self.fetch_interval - (time.monotonic() - last)), 1)

    @property
    def age_seconds(self) -> float | None:
        """Export staleness: seconds since the source file's mtime (falls
        back to the last good load when the file is gone)."""
        stamp = self._stat()
        if stamp is not None:
            return max(0.0, time.time() - stamp[0])
        with self._lock:
            loaded = self._loaded_at
        return max(0.0, time.time() - loaded) if loaded else None

    @property
    def last_error(self) -> str | None:
        with self._lock:
            return self._parse_error or self._fetch_error

    def matches(self, tags: Iterable[str]) -> list[PoolEntry]:
        """AND-match with negation: every want tag present AND no avoid
        tag.  "-"-prefixed request tags (``-asn:hosting``) are avoids.
        [] when neither wants nor avoids were asked."""
        self.reload()
        want = frozenset(t for t in (str(t).strip() for t in tags)
                         if t and not t.startswith("-"))
        avoid = frozenset(t[1:] for t in (str(t).strip() for t in tags)
                          if t.startswith("-"))
        if not want and not avoid:
            return []
        with self._lock:
            entries = self._entries
        return [e for e in entries
                if want <= e.tags and not (avoid & e.tags)]

    def choose(self, tags: Iterable[str],
               exclude: str | None = None) -> PoolEntry | None:
        """Random matching entry; ``exclude`` prefers a different exit (used
        by rotation) and is ignored when nothing else matches."""
        hits = self.matches(tags)
        if not hits:
            return None
        if exclude is not None:
            rest = [e for e in hits if e.url != exclude]
            if rest:
                hits = rest
        return random.choice(hits)

