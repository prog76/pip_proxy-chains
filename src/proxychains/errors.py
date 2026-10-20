"""Errors raised by the proxychains machinery.

``ProxySetupError`` is a *pool/config* fault (a tag matches nothing, an
unknown account in the injected tags hook, ...): it must surface immediately
and must NEVER trigger exit rotation. Applications subclass it to fuse it
with their own error hierarchy — a consumer, for example, uses
``class ProxySetupError(UpstreamError, proxychains.ProxySetupError)`` so the
same object is both an "upstream error" for failover display and a "setup
fault" for classify(). The owning ProxyChains instance then RAISES THE
APPLICATION'S CLASS (``setup_error=``), while classify() checks against the
base class defined here.
"""

from __future__ import annotations


class ProxySetupError(Exception):
    """Pool/config fault -- never rotate on it.

    Mirrors the historical app-side constructor ``(status, message)`` so call
    sites read ``ProxySetupError(503, "no proxy matches tags [...]")``.

    ``message`` is optional on purpose: in a mixin hierarchy
    (``class AppError(UpstreamError, ProxySetupError)``) the sibling base's
    ``__init__`` calls ``super().__init__(msg)`` with a single argument --
    that form must not touch ``.status`` (already set by the sibling).
    """

    def __init__(self, status: int, message: str | None = None):
        if message is None:
            super().__init__(status)  # mixin chain: message only, no status
            return
        self.status = status
        super().__init__(message)
