"""Masking (logs/status) + shared client-cache helpers."""

from __future__ import annotations

import asyncio
import urllib.parse

# Loopback client-cache bound: rotation creates a new listener URL per pin,
# so cached httpx clients accumulate -- evict + close beyond this many.
CLIENT_LRU = 50


def mask_host(host: str) -> str:
    """IPv4 keeps three octets + ``x``; IPv6 collapses; hostnames pass."""
    if host.count(":") >= 2:
        return "<ipv6>"
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:3] + ["x"])
    return host


def masked_url(url: str) -> str:
    """URL safe for logs/status: userinfo stripped, addresses masked."""
    if not url:
        return url
    raw = url if "://" in url else "http://" + url
    try:
        pr = urllib.parse.urlsplit(raw)
        host = pr.hostname or ""
        port = pr.port
    except ValueError:
        return "<invalid-proxy-url>"
    if not host:
        return "<invalid-proxy-url>"
    netloc = mask_host(host)
    if port:
        netloc = f"{netloc}:{port}"
    return f"{pr.scheme}://{netloc}"


async def _aclose_quiet(client) -> None:
    try:
        await client.aclose()
    except Exception:  # noqa: BLE001 -- best-effort close of an evicted client
        pass


def retire_soon(client, sink: list) -> None:
    """Close an evicted LRU client: schedule aclose() when a loop is running,
    otherwise park it in ``sink`` for the owner's close() (sync callers)."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        sink.append(client)
        return
    loop.create_task(_aclose_quiet(client))
