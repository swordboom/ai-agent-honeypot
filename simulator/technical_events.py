"""Repeatable Phase 1 technical scenarios using the public event contract."""

import time

from models.technical import TechnicalEvent


def _event(event_id, ip, users, count, *, domain=None, offset=0, succeeded=False, base=None):
    indicators = {"ip": [ip], "user": list(users)}
    if domain:
        indicators["domain"] = [domain]
    return TechnicalEvent(
        eventId=event_id,
        timestamp=(time.time() if base is None else base) + offset,
        eventType="AUTH_FAILURE_BURST",
        sourceIdentifier=ip,
        targetIdentifiers=list(users),
        indicators=indicators,
        count=count,
        confidence=0.9,
        detectionSource="technical-simulator",
        succeededAfterFailures=succeeded,
    )


def build(name: str, base: float = None):
    """Scenario events. `base` pins timestamps for tests; live callers get the wall
    clock, so a batch correlated with a running honeypot session spans minutes rather
    than years and the velocity dimension stays meaningful."""
    base = time.time() if base is None else base
    if name == "credential_stuffing":
        return [_event("credential-stuffing", "203.0.113.9", [f"user{i}" for i in range(12)], 50, succeeded=True, base=base)]
    if name == "password_spray":
        # A distinct source range: sharing 203.0.113.9 with the stuffing scenario
        # would (correctly) merge the two, which hides what this one demonstrates.
        return [_event(f"spray-{i}", f"198.51.100.{100 + i}", ["a.sharma"], 20, offset=i, base=base) for i in range(1, 31)]
    if name == "benign_failures":
        return [_event("benign-failures", "198.51.100.4", ["r.iyer"], 3, base=base)]
    if name == "cross_source":
        return [_event("cross-source-auth", "203.0.113.9", ["a.sharma", "v.rao"], 40, domain="secure-kyc-verify.tk", base=base)]
    raise ValueError(f"Unknown technical scenario: {name}")
