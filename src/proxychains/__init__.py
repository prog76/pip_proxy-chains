"""proxychains — tag-matched proxy chain egress (installable, stdlib-only).

Reusable machinery, deliberately decoupled from any particular application:

- :mod:`pool`       ChainPool: checker-export loading from a file or a URL
                    (periodic fetch, atomic writes, last-good retention) with
                    AND-match tag selection.
- :mod:`forwarder`  HTTP CONNECT forwarder, one listener per pinned
                    [entry ->] exit chain: loopback by default, bind policy
                    (LAN + Basic gate) provided by the resolver config.
- :mod:`resolver`   ProxyChains: pinning (optionally SESSION-scoped), exit
                    rotation, per-(scope, exit) QUARANTINE with TTL + sweep,
                    idle reap / pin caps, redacted status.
- :mod:`plans`      FailurePlan + classify(): rotate-vs-surface decisions with
                    PLUGGABLE rules — applications register their own HTTP
                    status/body rules (e.g. provider-specific gates) without
                    this package knowing anything about them.

Application seam: ProxyChains takes injected ``tags_for`` / ``explicit_for``
callables (how *your* app resolves tag lists and explicit proxies per
account/purpose) and a ``setup_error`` exception class (so the app's own
error type flows out of egress()). Quarantine keys and pin scopes are opaque
strings chosen by the caller (provider name, session id, ...).
"""

from __future__ import annotations

from .errors import ProxySetupError
from .forwarder import (
    ChainError,
    ChainListener,
    Proxy,
    nested_connect,
    split_proxy_url,
)
from .plans import (
    ROTATE_ATTEMPTS,
    ROTATE_STATUSES,
    SUPPORTED_SCHEMES,
    Context,
    FailurePlan,
    classify,
)
from .pool import ChainPool, PoolEntry
from .resolver import (
    ChainsConfig,
    Pin,
    ProxyChains,
    QuarantineStore,
    StageFailure,
    VERDICT_BUSY,
    VERDICT_DEAD,
    VERDICT_GATED,
    VERDICT_SERVES,
    VERDICT_STALE,
)
from .util import CLIENT_LRU, mask_host, masked_url, retire_soon

__version__ = "0.3.0"

__all__ = [
    "CLIENT_LRU",
    "ROTATE_ATTEMPTS",
    "ROTATE_STATUSES",
    "SUPPORTED_SCHEMES",
    "VERDICT_BUSY",
    "VERDICT_DEAD",
    "VERDICT_GATED",
    "VERDICT_SERVES",
    "VERDICT_STALE",
    "ChainError",
    "ChainListener",
    "ChainPool",
    "ChainsConfig",
    "Context",
    "FailurePlan",
    "Pin",
    "PoolEntry",
    "Proxy",
    "ProxyChains",
    "ProxySetupError",
    "QuarantineStore",
    "StageFailure",
    "classify",
    "mask_host",
    "masked_url",
    "nested_connect",
    "retire_soon",
    "split_proxy_url",
    "__version__",
]
