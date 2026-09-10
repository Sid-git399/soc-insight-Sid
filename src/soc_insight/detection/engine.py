"""
Detection engine.

Orchestrates: correlation windows -> each rule's evaluate() -> scoring.
This module intentionally contains no detection logic of its own -- that
lives in rules_data.py so rules stay independently testable and the engine
stays a thin, generic runner (see docs/detection-engine.md).
"""
from __future__ import annotations

from soc_insight.correlation import build_entity_windows
from soc_insight.models import DetectionMatch
from soc_insight.scoring import score_match
from .rules_data import ALL_RULES, Rule


def run_detection(events: list, window_minutes: int = 20, rules: list[Rule] | None = None) -> list[DetectionMatch]:
    rules = rules if rules is not None else ALL_RULES
    windows = build_entity_windows(events, window_minutes=window_minutes)

    results: list[DetectionMatch] = []
    for window in windows:
        for rule in rules:
            matches = rule.evaluate(window)
            for m in matches:
                score, severity, breakdown = score_match(rule.base_points, m.factors)
                results.append(
                    DetectionMatch(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        description=rule.description,
                        severity=severity,
                        base_confidence=rule.base_points,
                        mitre_technique=rule.mitre_technique,
                        explanation=m.explanation,
                        recommended_investigation=rule.recommended_investigation,
                        evidence_event_ids=m.evidence_event_ids,
                        entity_key=window.entity_key,
                        score=score,
                        score_breakdown=breakdown,
                        window_start=m.window_start,
                        window_end=m.window_end,
                    )
                )
    results.sort(key=lambda d: d.score, reverse=True)
    return results
