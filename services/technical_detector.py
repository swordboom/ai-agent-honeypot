"""Small, deterministic detector for authentication attack bursts."""

from dataclasses import dataclass


@dataclass(frozen=True)
class TechnicalDetection:
    is_threat: bool
    category: str = "UNKNOWN"
    triggers: tuple = ()


def classify(event_type: str, count: int, distinct_targets: int, succeeded: bool) -> TechnicalDetection:
    """Classify only meaningful auth bursts; routine login failures stay noise."""
    if event_type != "AUTH_FAILURE_BURST" or count < 10:
        return TechnicalDetection(False)
    if distinct_targets >= 5:
        return TechnicalDetection(True, "CREDENTIAL_STUFFING", ("many_accounts", "failure_burst"))
    if succeeded or count >= 20:
        return TechnicalDetection(True, "BRUTE_FORCE", ("failure_burst",))
    return TechnicalDetection(False)
