from soc_insight.mitre import get_technique, all_techniques
from soc_insight.detection.rules_data import ALL_RULES


def test_every_rule_maps_to_a_known_technique():
    for rule in ALL_RULES:
        tech = get_technique(rule.mitre_technique)
        assert tech is not None, f"{rule.rule_id} references unknown technique {rule.mitre_technique}"


def test_technique_has_required_fields():
    for tech in all_techniques():
        assert tech["id"]
        assert tech["name"]
        assert tech["tactic"]
        assert tech["description"]


def test_unknown_technique_returns_none():
    assert get_technique("T9999.999") is None
