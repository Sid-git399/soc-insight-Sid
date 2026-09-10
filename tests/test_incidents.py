from pathlib import Path

from soc_insight.pipeline import Pipeline

SCENARIOS = Path(__file__).parent.parent / "data" / "scenarios"


def build_pipeline():
    p = Pipeline()
    p.load_demo_data(str(SCENARIOS))
    p.run_pipeline()
    return p


def test_five_incidents_created_from_demo_data():
    p = build_pipeline()
    assert len(p.incidents) == 5


def test_incident_ids_follow_expected_format():
    p = build_pipeline()
    for incident in p.incidents:
        assert incident.incident_id.startswith("INC-")
        parts = incident.incident_id.split("-")
        assert len(parts) == 3
        assert parts[1].isdigit()
        assert parts[2].isdigit()


def test_incident_default_status_and_classification():
    p = build_pipeline()
    for incident in p.incidents:
        assert incident.status == "NEW"
        assert incident.classification == "UNRESOLVED"


def test_incident_status_transitions():
    p = build_pipeline()
    incident = p.incidents[0]
    incident.status = "INVESTIGATING"
    assert p.get_incident(incident.incident_id).status == "INVESTIGATING"


def test_incident_can_be_marked_false_positive():
    p = build_pipeline()
    incident = p.incidents[0]
    incident.classification = "FALSE_POSITIVE"
    assert p.get_incident(incident.incident_id).classification == "FALSE_POSITIVE"


def test_incident_has_timeline_in_chronological_order():
    p = build_pipeline()
    for incident in p.incidents:
        timestamps = [e["timestamp"] for e in incident.timeline]
        assert timestamps == sorted(timestamps)


def test_incident_to_dict_includes_investigation_context():
    p = build_pipeline()
    incident = p.incidents[0]
    d = p.incident_to_dict(incident)
    assert "_recommended_investigation" in d
    assert len(d["_recommended_investigation"]) > 0
    assert "attack_chain" in d
    assert "detections" in d


def test_incident_notes_can_be_added():
    p = build_pipeline()
    incident = p.incidents[0]
    incident.analyst_notes.append({"timestamp": "2026-01-01T00:00:00Z", "author": "analyst1", "note": "Reviewed evidence."})
    assert len(p.get_incident(incident.incident_id).analyst_notes) == 1


def test_evidence_classification_tracking():
    p = build_pipeline()
    incident = p.incidents[0]
    event_id = incident.event_ids[0]
    incident.evidence_classifications[event_id] = "CONFIRMED"
    assert p.get_incident(incident.incident_id).evidence_classifications[event_id] == "CONFIRMED"
