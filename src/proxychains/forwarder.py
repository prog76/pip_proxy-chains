"""Loopback forwarder: stdlib sockets in threads, one nested-CONNECT tunnel
per request, client body forwarded AFTER the rewritten head. Includes a
failure hook for stage attribution; stage-tagged failures are logged at
WARNING WITHOUT detail (chain error strings embed entry/exit addresses),
and _CONNECT_TIMEOUT=12 as explained below.

Forwarder I/O.  _CONNECT_TIMEOUT is deliberately BELOW httpx's 15s connect
timeout: the forwarder must fail first so its stage record is in place
before httpx raises, otherwise a slow dial cannot be attributed to entry
vs exit.
"""

from __future__ import annotations

import base64
import hmac
import logging
import socket
import socketserver
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 12
_HEAD_LIMIT = 65536
_RELAY_IDLE_TIMEOUT = 300


class ChainError(RuntimeError):
    """Stage-tagged failure so callers attribute blame correctly.

    stage: "entry" | "exit" | "target"
    kind:  "conn" (dial/refused) | "http" (proxy answered >=400) | "proto"
    """

    def __init__(self, msg: str, stage: str, kind: str = "proto"):
        super().__init__(msg)
        self.stage = stage
        self.kind = kind


class _ProtoErr(Exception):
    """Protocol-level failure reading a head (not stage-tagged)."""


@dataclass
class Proxy:
    """A proxy endpoint: url with optional scheme and embedded credentials."""

    url: str


def split_proxy_url(url: str) -> tuple[str, str, int, str, str]:
    """scheme, host, port, user, password (userinfo url-decoded)."""
    if "://" not in url:
        url = "http://" + url
    pr = urllib.parse.urlsplit(url)
    scheme = pr.scheme or "http"
    host = pr.hostname or ""
    port = pr.port or (443 if scheme == "https" else 80)
    user = urllib.parse.unquote(pr.username or "")
    pw = urllib.parse.unquote(pr.password or "")
    return scheme, host, port, user, pw


def _basic_auth(user: str, pw: str) -> str | None:
    if not user:
        return None
    tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return f"Basic {tok}"


def _read_head(sock: socket.socket) -> tuple[bytes, bytes]:
    """Read up to and including CRLFCRLF; return (head, leftover)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, OSError) as e:
            raise _ProtoErr(f"peer closed during headers: {e}") from e
        if not chunk:
            raise _ProtoErr("peer closed during headers")
        buf += chunk
        if len(buf) > _HEAD_LIMIT:
            raise _ProtoErr("headers too large")
    head, leftover = buf.split(b"\r\n\r\n", 1)
    return head + b"\r\n\r\n", leftover


def _status_code(head: bytes) -> int:
    try:
        return int(head.split(b"\r\n", 1)[0].split()[1])
    except (IndexError, ValueError) as e:
        raise _ProtoErr(f"bad status line: {head[:80]!r}") from e


def _send_connect(sock: socket.socket, authority: str,
                  auth_header: str | None) -> None:
    lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}"]
    if auth_header:
        lines.append(f"Proxy-Authorization: {auth_header}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
def nested_connect(entry: "Proxy | None", exitp: Proxy, target_host: str,
                   target_port: int,
                   timeout: float = _CONNECT_TIMEOUT) -> tuple[socket.socket, bytes]:
    """Build the [entry ->] exit -> target tunnel; returns (socket, leftover).

    leftover = tunnel-side bytes already read past the exit's 200 response.
    Raises ChainError with stage/kind attribution: entry/conn and
    entry/407 are the entry's fault; the rest -- including entry/proto,
    where a squid-like entry closes on ITS upstream dial failure -- point
    at the exit.
    """
    sock: socket.socket | None = None
    leftover = b""

    if entry is not None:
        # Stage 1: dial the entry, ask it to CONNECT to the exit.
        _, ehost, eport, euser, epw = split_proxy_url(entry.url)
        _, xhost, xport, _, _ = split_proxy_url(exitp.url)
        try:
            sock = socket.create_connection((ehost, eport), timeout)
        except OSError as e:
            raise ChainError(f"entry unreachable: {e}", "entry", "conn") from e
        try:
            _send_connect(sock, f"{xhost}:{xport}", _basic_auth(euser, epw))
            head, leftover = _read_head(sock)
            code = _status_code(head)
        except _ProtoErr as e:
            sock.close()
            raise ChainError(str(e), "entry", "proto") from e
        except OSError as e:
            sock.close()
            raise ChainError(f"entry tunnel write failed: {e}", "entry", "conn") from e
        if code != 200:
            sock.close()
            if code == 407:
                raise ChainError("entry proxy auth rejected", "entry", "http")
            if code == 403:
                raise ChainError(f"entry refused CONNECT to exit port {xport}",
                                 "exit", "http")
            raise ChainError(f"entry upstream error HTTP {code}", "exit", "http")
    else:
        # Direct to the exit (1-hop tag pin: no entry configured).
        _, xhost, xport, _, _ = split_proxy_url(exitp.url)
        try:
            sock = socket.create_connection((xhost, xport), timeout)
        except OSError as e:
            raise ChainError(f"exit unreachable: {e}", "exit", "conn") from e

    # Stage 2/3: CONNECT to the target, spoken to the exit proxy (directly or
    # inside the entry tunnel).
    _, _, _, xuser, xpw = split_proxy_url(exitp.url)
    try:
        _send_connect(sock, f"{target_host}:{target_port}", _basic_auth(xuser, xpw))
        head, resp_left = _read_head(sock)
        code = _status_code(head)
    except _ProtoErr as e:
        sock.close()
        raise ChainError(str(e), "exit", "proto") from e
    except OSError as e:
        sock.close()
        raise ChainError(f"tunnel write failed: {e}", "exit", "conn") from e
    if code != 200:
        sock.close()
        if code in (405, 501, 407):
            raise ChainError(f"exit proxy rejected CONNECT (HTTP {code})",
                             "exit", "http")
        raise ChainError(
            f"cannot reach {target_host}:{target_port} via exit (HTTP {code})",
            "target", "http")
    if leftover:
        resp_left = leftover + resp_left
    return sock, resp_left


def _relay(src: socket.socket, dst: socket.socket) -> None:
    """src -> dst until EOF/error; half-close dst when src ends."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _relay_body(src: socket.socket, dst: socket.socket, initial: bytes) -> None:
    """Relay body bytes after writing any initial leftover."""
    if initial:
        try:
            dst.sendall(initial)
        except OSError:
            return
    _relay(src, dst)


def _pump(client: socket.socket, tunnel: socket.socket,
          to_tunnel: bytes = b"", from_tunnel: bytes = b"") -> None:
    """Forward client->tunnel (with any queued head/body) and the response."""
    if to_tunnel:
        try:
            tunnel.sendall(to_tunnel)
        except OSError:
            return
    t = threading.Thread(
        target=lambda: (_relay_body(tunnel, client, from_tunnel), None),
        daemon=True,
    )
    t.start()
    _relay(client, tunnel)
    t.join(timeout=5)
def _rewrite_head(head: bytes, method: str, target: str, version: str,
                  host: str, port: int) -> bytes:
    """Absolute-form request head for the exit tunnel.

    Terminate the head properly exactly once (re-terminating it is what
    fixed the original forwarder's POST-body corruption: stray CRLFCRLF in
    front of the body desyncs Content-Length framing), keep absolute-form
    targets, strip proxy-hop headers (Proxy-*), drop Connection: keep-alive
    so the exchange ends at one request/response.
    """
    lines = head.decode("latin-1").split("\r\n")
    while lines and lines[-1] == "":
        lines.pop()
    if not target.startswith(("http://", "https://")):
        authority = host if port in (80, 443) else f"{host}:{port}"
        path = target if target.startswith("/") else "/" + target
        lines[0] = f"{method} http://{authority}{path} {version}"
    out = [lines[0]]
    has_host = False
    for ln in lines[1:]:
        low = ln.lower()
        if low.startswith("proxy-"):
            continue
        if low.startswith("host:"):
            has_host = True
        if low.startswith("connection:"):
            continue
        out.append(ln)
    if not has_host:
        authority = host if port in (80, 443) else f"{host}:{port}"
        out.append(f"Host: {authority}")
    out.append("Connection: close")
    return ("\r\n".join(out) + "\r\n\r\n").encode("latin-1")


def _authority(value: str, default_port: int) -> tuple[str, int]:
    if ":" in value:
        h, _, p = value.rpartition(":")
        try:
            return h, int(p)
        except ValueError:
            return value, default_port
    return value, default_port


def _auth_ok(head: bytes, expected: str | None) -> bool:
    """Proxy-Authorization gate; ``expected`` None = loopback, no gate."""
    if expected is None:
        return True
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"proxy-authorization:"):
            got = line.split(b":", 1)[1].strip().decode("latin-1")
            return hmac.compare_digest(got, expected)
    return False


def _serve_one(client: socket.socket, listener: "ChainListener") -> None:
    client.settimeout(_CONNECT_TIMEOUT)
    head, leftover = _read_head(client)
    first = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = first.split()
    if len(parts) < 3:
        raise _ProtoErr(f"bad request line: {first!r}")
    method, target, version = parts[0], parts[1], parts[2]

    if not _auth_ok(head, listener.auth):
        client.sendall(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b'Proxy-Authenticate: Basic realm="proxychains"\r\n'
            b"Content-Length: 0\r\n\r\n")
        return

    entry, exitp = listener.entry, listener.exit

    if method == "CONNECT":
        host, port = _authority(target, 443)
        tunnel, resp_left = nested_connect(entry, exitp, host, port)
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        client.settimeout(_RELAY_IDLE_TIMEOUT)
        tunnel.settimeout(_RELAY_IDLE_TIMEOUT)
        _pump(client, tunnel, to_tunnel=leftover, from_tunnel=resp_left)
        return

    # plain HTTP: resolve target from the absolute URL or the Host header
    if target.startswith(("http://", "https://")):
        pr = urllib.parse.urlsplit(target)
        host = pr.hostname or ""
        port = pr.port or (443 if pr.scheme == "https" else 80)
    else:
        host_hdr = ""
        for ln in head.decode("latin-1").split("\r\n")[1:]:
            if ln.lower().startswith("host:"):
                host_hdr = ln.split(":", 1)[1].strip()
                break
        host, port = _authority(host_hdr, 80)
    if not host:
        raise _ProtoErr("no target host")

    tunnel, resp_left = nested_connect(entry, exitp, host, port)
    new_head = _rewrite_head(head, method, target, version, host, port)
    client.settimeout(_RELAY_IDLE_TIMEOUT)
    tunnel.settimeout(_RELAY_IDLE_TIMEOUT)
    # POST-body fix (design): forward the client body AFTER the rewritten
    # head -- the original only sent new_head and silently dropped bodies.
    _pump(client, tunnel, to_tunnel=new_head + leftover, from_tunnel=resp_left)
@dataclass
class ChainListener:
    """A live forwarder bound to one [entry ->] exit chain: loopback by
    default; binds and credentials follow the resolver bind policy."""

    entry: Proxy | None
    exit: Proxy
    url: str
    server: "socketserver.ThreadingTCPServer"
    thread: threading.Thread | None
    last_used: float
    active: int = 0
    on_failure: Callable[[str, str], None] | None = None
    auth: str | None = None

    def record_failure(self, stage: str, kind: str) -> None:
        """Hand a stage-tagged failure to the resolver (thread-safe, and it
        runs BEFORE the client socket closes -- so the record is always in
        place by the time httpx sees the disconnect)."""
        cb = self.on_failure
        if cb is not None:
            try:
                cb(stage, kind)
            except Exception:
                log.exception("chain failure hook crashed")

    def close(self) -> None:
        try:
            self.server.shutdown()
            self.server.server_close()
        except OSError:
            pass


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        listener: ChainListener = self.server.listener  # type: ignore[attr-defined]
        listener.last_used = time.time()
        listener.active += 1
        try:
            _serve_one(self.request, listener)
        except ChainError as e:
            # WARNING without detail: ChainError strings embed the entry and
            # exit addresses (never log those).  stage/kind is the signal.
            log.warning("chain failure stage=%s kind=%s", e.stage, e.kind)
            listener.record_failure(e.stage, e.kind)
        except _ProtoErr as e:
            log.debug("chain proto error: %s", e)
        except OSError as e:
            log.debug("chain io error: %s", e)
        except Exception:
            log.exception("chain handler crashed")
        finally:
            listener.active -= 1
            listener.last_used = time.time()
            try:
                self.request.close()
            except OSError:
                pass


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    listener: ChainListener



