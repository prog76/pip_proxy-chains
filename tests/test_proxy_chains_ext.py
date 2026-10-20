"""Extension tests: scheme filter at load, tag negation, bind policy + auth.

No external network: every socket binds to 127.0.0.1 (the wildcard bind
guard test never creates a listener).
"""
from __future__ import annotations

import base64
import json
import socket
import threading
import urllib.parse

import pytest

from proxychains.errors import ProxySetupError
from proxychains.pool import ChainPool
from proxychains.resolver import ChainsConfig, ProxyChains



def _feed(tmp_path, entries):
    p = tmp_path / "feed.json"
    p.write_text(json.dumps({"proxies": entries}), encoding="utf-8")
    return p


def test_scheme_filter_drops_unsupported(tmp_path):
    feed = _feed(tmp_path, [
        {"proxy": "10.0.0.1:8080", "scheme": "http", "tags": ["alive"]},
        {"proxy": "10.0.0.2:8080", "scheme": "socks4", "tags": ["alive"]},
        {"proxy": "10.0.0.3:8080", "scheme": "socks5", "tags": ["alive"]},
        {"proxy": "10.0.0.4:8080", "scheme": "gopher", "tags": ["alive"]},
    ])
    pool = ChainPool(str(feed), refresh=1)
    urls = [e.url for e in pool.matches(["alive"])]
    assert sorted(urls) == ["http://10.0.0.1:8080", "socks5://10.0.0.3:8080"]


def test_tag_negation(tmp_path):
    feed = _feed(tmp_path, [
        {"proxy": "10.0.0.1:8001", "scheme": "http",
         "tags": ["alive", "asn:hosting"]},
        {"proxy": "10.0.0.2:8002", "scheme": "http",
         "tags": ["alive", "asn:isp"]},
    ])
    pool = ChainPool(str(feed), refresh=1)
    assert [e.url for e in pool.matches(["asn:hosting"])] == \
        ["http://10.0.0.1:8001"]
    assert [e.url for e in pool.matches(["-asn:hosting"])] == \
        ["http://10.0.0.2:8002"]
    assert [e.url for e in pool.matches(["alive", "-asn:hosting"])] == \
        ["http://10.0.0.2:8002"]
    assert pool.matches(["asn:hosting", "-asn:hosting"]) == []
    assert pool.matches([]) == []


def test_wildcard_bind_requires_credentials(tmp_path):
    feed = _feed(tmp_path, [])
    with pytest.raises(ProxySetupError, match="bind_host outside loopback"):
        ProxyChains(ChainsConfig(path=str(feed), bind_host="0.0.0.0"))
    ch = ProxyChains(ChainsConfig(path=str(feed), bind_host="0.0.0.0",
                                  bind_user="u", bind_pass="p"))
    ch.close()


def _raw_connect(url, auth=None, target="127.0.0.1:1", timeout=5):
    """Hand-rolled CONNECT through the listener; returns the response head."""
    pr = urllib.parse.urlsplit(url)
    req = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
    if auth:
        req += f"Proxy-Authorization: {auth}\r\n"
    req += "\r\n"
    with socket.create_connection((pr.hostname, pr.port), timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(req.encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                break
            head += chunk
        return head


def test_auth_gate_end_to_end(tmp_path, monkeypatch):
    monkeypatch.delenv("PROXIES_ENTRY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    target = _EchoTarget()
    exitp = _MiniProxy()
    chains = None
    try:
        feed = _feed(tmp_path, [
            {"proxy": f"127.0.0.1:{exitp.port}", "scheme": "http",
             "tags": ["llm"]},
        ])
        chains = ProxyChains(
            ChainsConfig(path=str(feed), refresh=1,
                         bind_user="u", bind_pass="p"),
            tags_for=lambda account, purpose: ["llm"])
        url = chains.egress("acct/x", "api")
        assert url.startswith("http://u:p@"), url

        # no credentials -> 407 before the exit is ever dialed
        head = _raw_connect(url, target=target.hostport)
        assert b"407" in head.split(b"\r\n")[0], head
        assert exitp.connects == []

        # wrong credentials -> still 407
        head = _raw_connect(url, auth="Basic ZGVhZDpiZWVm",
                            target=target.hostport)
        assert b"407" in head.split(b"\r\n")[0], head
        assert exitp.connects == []

        # correct credentials -> tunnel; the exit sees the CONNECT
        good = "Basic " + base64.b64encode(b"u:p").decode()
        head = _raw_connect(url, auth=good, target=target.hostport)
        assert b"200" in head.split(b"\r\n")[0], head
        assert exitp.connects == [target.hostport]
    finally:
        if chains is not None:
            chains.close()
        target.close()
        exitp.close()


class _MiniProxy:
    """Minimal HTTP-CONNECT proxy: records CONNECT targets and relays bytes."""

    def __init__(self, refuse: bool = False):
        self.connects: list[str] = []
        self._refuse = refuse
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()
        try:
            self._srv.close()
        except OSError:
            pass

    def _handle(self, conn: socket.socket) -> None:
        up = None
        try:
            conn.settimeout(10)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            first = buf.split(b"\r\n", 1)[0].decode("latin-1").split()
            if len(first) < 2 or first[0] != "CONNECT":
                conn.sendall(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                return
            authority = first[1]
            self.connects.append(authority)
            if self._refuse:
                conn.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return
            host, _, port = authority.rpartition(":")
            up = socket.create_connection((host, int(port)), 5)
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            def pump(src, dst):
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

            t = threading.Thread(target=pump, args=(up, conn), daemon=True)
            t.start()
            pump(conn, up)
            t.join(5)
        except Exception:
            pass
        finally:
            for s in (conn, up):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    def close(self) -> None:
        self._stop.set()
        try:
            socket.create_connection(("127.0.0.1", self.port), 1).close()
        except OSError:
            pass


class _EchoTarget:
    """Plain-HTTP echo: records (method, target, body) and echoes the body."""

    def __init__(self):
        self.requests: list[dict] = []
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        self.hostport = f"127.0.0.1:{self.port}"
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()
        try:
            self._srv.close()
        except OSError:
            pass

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(10)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head, rest = buf.split(b"\r\n\r\n", 1)
            lines = head.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split()
            length = 0
            for ln in lines[1:]:
                if ln.lower().startswith("content-length:"):
                    length = int(ln.split(":", 1)[1].strip())
            while len(rest) < length:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                rest += chunk
            body = rest[:length]
            self.requests.append({"method": method, "target": target,
                                  "body": body})
            payload = body  # echo the body back verbatim
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                + f"Content-Length: {len(payload)}\r\n".encode()
                + b"Connection: close\r\n\r\n" + payload
            )
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        try:
            socket.create_connection(("127.0.0.1", self.port), 1).close()
        except OSError:
            pass
