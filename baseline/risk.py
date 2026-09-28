"""
Risk scoring engine.

Implements a simple, defensible likelihood x impact model in the spirit of
ISO 31000: every failed control produces a risk with a likelihood rating
(how exposed / easy to exploit) and an impact rating (how bad the outcome
would be), multiplied into a risk score and mapped to a risk level.

This is intentionally simple (a 5x5 matrix) rather than a full quantitative
model -- the goal is a defensible, explainable method suitable for a
consultative / advisory context, not a precise probability estimate.
"""

from dataclasses import dataclass
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class RiskRating:
    likelihood: int   # 1 (rare) - 5 (almost certain)
    impact: int        # 1 (negligible) - 5 (severe)

    @property
    def score(self) -> int:
        return self.likelihood * self.impact

    @property
    def level(self) -> RiskLevel:
        s = self.score
        if s <= 4:
            return RiskLevel.LOW
        if s <= 9:
            return RiskLevel.MEDIUM
        if s <= 16:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL


def likelihood_for(check_result: dict) -> int:
    """
    Derive a likelihood rating from characteristics of a failed check.

    Exposure to an untrusted network raises likelihood; a finding that only
    applies internally (e.g. missing centralized logging) is rated lower,
    since it doesn't directly increase the chance of initial compromise.
    """
    exposure = check_result.get("exposure", "internal")
    if exposure == "internet":
        return 5
    if exposure == "internal_untrusted":
        return 4
    if exposure == "internal_trusted":
        return 2
    return 3  # unknown / default


def rate_finding(control, check_result: dict) -> RiskRating:
    likelihood = likelihood_for(check_result)
    impact = check_result.get("impact_override", control.default_impact)
    return RiskRating(likelihood=likelihood, impact=impact)
