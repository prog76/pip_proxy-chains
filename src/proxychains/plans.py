"""Failure classification: rotate-vs-surface for one failed attempt.

The DEFAULT rules here are transport-generic: dead-exit HTTP statuses and
stage-attributed transport failures. Application-specific rules (IP verdicts,
provider gates such as Zen's 403 FreeTierError network block, ...) are passed
in by the caller via ``classify(..., rules=...)`` — first rule returning a
plan wins, so the application layer never has to fork this module and this
module never learns what a "provider" is.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Sequence

from .errors import ProxySetupError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .resolver import ProxyChains

# Direct-URL schemes httpx accepts (documented in config.example.yaml).
SUPPORTED_SCHEMES = ("http", "https", "socks5", "socks5h")
# HTTP statuses that mean "this egress is unusable" -> rotate the exit.
ROTATE_STATUSES = frozenset({407, 502, 503, 504})
# Total same-account attempts after an exit-dead failure (initial + rotations).
ROTATE_ATTEMPTS = 3


@dataclass
class FailurePlan:
    """What to do about one failed attempt (see :func:`classify`)."""

    action: str = ""   # "" surface | "entry" surface (entry's fault)
    #                    | "rotate" exit-dead | "verdict" IP verdict
    attempts: int = 1  # total same-account attempts this failure class allows
    stage: str = ""    # chain attribution when a fresh stage record exists
    kind: str = ""
    # Opaque application key: when set, the exit is QUARANTINED for this key
    # (app-defined scope, e.g. a provider name) and pins sharing it are swept
    # off the exit before the rotation picks a fresh one.
    quarantine_scope: str = ""
    # Per-verdict cooldown override (0 = the store default).  Verdicts carry
    # very different half-lives: a 403 IP gate is a reputation verdict (hours)
    # while a 429 rate hit cools in minutes.
    cooldown_seconds: float = 0.0
    # Rotation should only consider PREFLIGHT-PROVEN (warm/works) exits --
    # used by the 429 rate rule so a retry never burns a cold candidate.
    warm_only: bool = False


@dataclass(frozen=True)
class Context:
    """Everything a rule may inspect about one failed attempt."""

    status: int
    text: str
    exc: BaseException | None
    account: str
    purpose: str
    scope: str            # pin scope (session id or "")
    provider_name: str    # app-defined label (opaque to this package)


Rule = Callable[[Context], "FailurePlan | None"]


def classify(
    chains: "ProxyChains | None",
    account: str,
    purpose: str,
    status: int,
    text: str,
    exc: BaseException | None = None,
    *,
    scope: str = "",
    provider_name: str = "",
    rules: Sequence[Rule] | None = None,
) -> FailurePlan:
    """Decide rotate-vs-surface for one failed attempt.

    ``status`` 0 means transport-level (no HTTP response): chain failures
    never produce a status -- the forwarder closes the socket -- so transport
    failures attribute through the pin's fresh stage record.  Application
    ``rules`` run before the built-in table (the default for 429 cools the
    account and never rotates -- an app rule may claim it, e.g. exit-scoped
    rate-limit rotation; 407/502/503/504 mean the egress itself is unusable).
    ProxySetupError is a config fault and always surfaces.
    """
    if isinstance(exc, ProxySetupError):
        return FailurePlan()
    ctx = Context(status=status, text=text or "", exc=exc, account=account,
                  purpose=purpose, scope=scope or "", provider_name=provider_name)
    if rules:
        for rule in rules:
            plan = rule(ctx)
            if plan is not None:
                return plan
    if status == 429:
        return FailurePlan()  # default: cool the account, no rotation
    if status in ROTATE_STATUSES:
        return FailurePlan(action="rotate", attempts=ROTATE_ATTEMPTS)
    if not status:  # transport-level: attribute via the fresh stage record
        action, stage, kind = "", "", ""
        if chains is not None:
            action, stage, kind = chains.stage_action(account, purpose, scope)
        if action == "entry":
            return FailurePlan(action="entry", stage=stage, kind=kind)
        if action == "exit":
            return FailurePlan(action="rotate", attempts=ROTATE_ATTEMPTS,
                               stage=stage, kind=kind)
    return FailurePlan()
