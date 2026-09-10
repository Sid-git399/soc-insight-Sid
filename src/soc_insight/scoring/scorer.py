"""
Risk scoring.

Deliberately simple and auditable: final_score = base_points + sum(factor
points), clamped to [0, 100]. The UI always renders the full breakdown
(see docs/detection-engine.md) so an analyst can see exactly how a number
was produced -- there is no hidden "AI confidence" figure.
"""
from __future__ import annotations

from soc_insight.models import severity_from_score


def score_match(base_points: int, factors: list) -> tuple[int, str, list]:
    """
    factors: list of (label, points)
    Returns (score, severity_label, breakdown) where breakdown is a list of
    {"factor": str, "points": int} dicts starting with the base severity.
    """
    breakdown = [{"factor": "base severity for this detection pattern", "points": base_points}]
    total = base_points
    for label, points in factors:
        breakdown.append({"factor": label, "points": points})
        total += points
    total = max(0, min(100, total))
    severity = severity_from_score(total)
    return total, severity, breakdown
