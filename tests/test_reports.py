from pathlib import Path

from soc_insight.pipeline import Pipeline
from soc_insight.reports import generate_report

SCENARIOS = Path(__file__).parent.parent / "data" / "scenarios"


def build_pipeline():
    p = Pipeline()
    p.load_demo_data(str(SCENARIOS))
    p.run_pipeline()
    return p


def test_report_contains_required_sections():
    p = build_pipeline()
    incident = p.incidents[0]
    incident_dict = p.incident_to_dict(incident)
    all_iocs = [i.to_dict() for i in p.iocs]
    report = generate_report(incident_dict, all_iocs)

    required_sections = [
        "SOC-INSIGHT INCIDENT REPORT",
        "Executive Summary",
        "Incident Classification",
        "Affected Assets",
        "Timeline",
        "Detection Evidence",
        "Indicators of Compromise",
        "MITRE ATT&CK Mapping",
        "Analyst Findings",
        "Recommended Actions",
        "Final Classification",
    ]
    for section in required_sections:
        assert section in report, f"missing section: {section}"


def test_report_includes_incident_id():
    p = build_pipeline()
    incident = p.incidents[0]
    incident_dict = p.incident_to_dict(incident)
    all_iocs = [i.to_dict() for i in p.iocs]
    report = generate_report(incident_dict, all_iocs)
    assert incident.incident_id in report


def test_report_notes_simulation_environment():
    p = build_pipeline()
    incident = p.incidents[0]
    incident_dict = p.incident_to_dict(incident)
    all_iocs = [i.to_dict() for i in p.iocs]
    report = generate_report(incident_dict, all_iocs)
    assert "Simulation" in report or "simulation" in report


def test_report_reflects_analyst_notes():
    p = build_pipeline()
    incident = p.incidents[0]
    incident.analyst_notes.append({"timestamp": "2026-01-01T00:00:00Z", "author": "analyst1", "note": "Confirmed with account owner: not authorized."})
    incident_dict = p.incident_to_dict(incident)
    all_iocs = [i.to_dict() for i in p.iocs]
    report = generate_report(incident_dict, all_iocs)
    assert "Confirmed with account owner" in report
