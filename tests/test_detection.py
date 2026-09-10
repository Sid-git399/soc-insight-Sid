from pathlib import Path

from soc_insight.detection.engine import run_detection
from soc_insight.ingestion import load_file

FIXTURES = Path(__file__).parent / "fixtures"
SCENARIOS = Path(__file__).parent.parent / "data" / "scenarios"


def load_all_scenarios():
    events = []
    for f in sorted(SCENARIOS.glob("*")):
        if f.is_file():
            evts, issues = load_file(f)
            assert issues == [], f"unexpected ingestion issues for {f.name}: {issues}"
            events.extend(evts)
    return events


def test_brute_force_scenario_detected():
    events = load_all_scenarios()
    detections = run_detection(events)
    rule_ids = {d.rule_id for d in detections}
    assert "RULE-AUTH-001" in rule_ids
    match = next(d for d in detections if d.rule_id == "RULE-AUTH-001")
    assert match.severity in ("HIGH", "CRITICAL")
    assert match.score >= 75


def test_powershell_scenario_detected_with_escalation():
    events = load_all_scenarios()
    detections = run_detection(events)
    match = next(d for d in detections if d.rule_id == "RULE-PS-001")
    factor_labels = [f["factor"] for f in match.score_breakdown]
    assert any("encoded" in f.lower() for f in factor_labels)
    assert any("network" in f.lower() for f in factor_labels)


def test_persistence_scenario_detected():
    events = load_all_scenarios()
    detections = run_detection(events)
    assert any(d.rule_id == "RULE-PERSIST-001" for d in detections)


def test_lateral_movement_scenario_detected():
    events = load_all_scenarios()
    detections = run_detection(events)
    assert any(d.rule_id == "RULE-LATERAL-001" for d in detections)


def test_exfiltration_scenario_detected():
    events = load_all_scenarios()
    detections = run_detection(events)
    match = next(d for d in detections if d.rule_id == "RULE-EXFIL-001")
    assert match.score >= 75


def test_plain_powershell_does_not_trigger_rule():
    """Section 29 requirement: a legitimate PowerShell command should NOT
    automatically become a critical detection."""
    events, issues = load_file(FIXTURES / "benign_activity.json")
    assert issues == []
    detections = run_detection(events)
    assert not any(d.rule_id == "RULE-PS-001" for d in detections)


def test_few_failed_logins_do_not_trigger_brute_force():
    events, issues = load_file(FIXTURES / "benign_activity.json")
    detections = run_detection(events)
    assert not any(d.rule_id == "RULE-AUTH-001" for d in detections)


def test_standalone_scheduled_task_is_not_critical():
    """Scheduled task alone (no preceding suspicious admin activity) should
    stay at a lower severity band per the scoring spec."""
    events, issues = load_file(FIXTURES / "benign_activity.json")
    detections = run_detection(events)
    match = next((d for d in detections if d.rule_id == "RULE-PERSIST-001"), None)
    assert match is not None
    assert match.severity in ("LOW", "MEDIUM")


def test_every_detection_has_explainability_fields():
    events = load_all_scenarios()
    detections = run_detection(events)
    for d in detections:
        assert d.explanation
        assert d.recommended_investigation
        assert d.mitre_technique
        assert d.evidence_event_ids
        assert d.score_breakdown
