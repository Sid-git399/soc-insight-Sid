"""
RuleBasedProvider -- the default AIProvider.

Produces incident narratives directly from the detection evidence that is
already on the incident (rule explanations, MITRE mapping, score
breakdown). This is deliberately template-based rather than a black box:
every sentence traces back to a specific field on the incident, and
confidence language is scaled to the evidence classification and score
rather than asserted uniformly.
"""
from __future__ import annotations

from soc_insight.analysis.ai_provider import AIProvider
from soc_insight.mitre import get_technique


def _confidence_phrase(score: int, classification: str) -> str:
    if classification == "FALSE_POSITIVE":
        return "This incident has been classified as a false positive by an analyst."
    if classification == "BENIGN_ACTIVITY":
        return "This incident has been classified as benign activity by an analyst."
    if score >= 90:
        return "The evidence collected strongly supports this classification."
    if score >= 75:
        return "The evidence collected provides strong, but not conclusive, support for this classification."
    if score >= 50:
        return "The evidence is suggestive but not conclusive; manual verification is recommended."
    return "The evidence is limited; this may be a false positive and warrants manual review before escalation."


class RuleBasedProvider(AIProvider):
    def summarize_incident(self, incident: dict) -> str:
        hosts = ", ".join(incident.get("affected_hosts") or []) or "an unspecified host"
        users = ", ".join(incident.get("affected_users") or []) or "an unspecified account"
        techniques = incident.get("mitre_techniques") or []
        technique_names = []
        for tid in techniques:
            tech = get_technique(tid)
            if tech:
                technique_names.append(f"{tech['name']} ({tid})")
        technique_text = "; ".join(technique_names) if technique_names else "no mapped technique"

        summary = (
            f"Incident {incident.get('incident_id')} involves account(s) {users} on host(s) {hosts}. "
            f"Detected behavior maps to: {technique_text}. "
            f"Current risk score is {incident.get('score')}/100 ({incident.get('severity')}). "
        )
        summary += _confidence_phrase(incident.get("score", 0), incident.get("classification", "UNRESOLVED"))
        return summary

    def explain_evidence(self, incident: dict) -> list:
        explanations = []
        for entry in incident.get("timeline", []):
            explanations.append({
                "event_id": entry.get("event_id"),
                "timestamp": entry.get("timestamp"),
                "explanation": f"{entry.get('title')} — {entry.get('detail')}",
            })
        return explanations

    def investigation_suggestions(self, incident: dict) -> list:
        # Investigation guidance is sourced from the rules that fired; this
        # method just deduplicates and orders it for presentation.
        suggestions = list(dict.fromkeys(incident.get("_recommended_investigation", [])))
        if not suggestions:
            suggestions = [
                "Review the raw evidence events for this incident.",
                "Confirm whether the account owner and host owner performed this activity.",
            ]
        return suggestions

    def executive_summary(self, incident: dict) -> str:
        severity_word = {
            "CRITICAL": "a critical-priority",
            "HIGH": "a high-priority",
            "MEDIUM": "a moderate-priority",
            "LOW": "a low-priority",
            "INFO": "an informational",
        }.get(incident.get("severity"), "an")
        hosts = len(incident.get("affected_hosts") or [])
        users = len(incident.get("affected_users") or [])
        return (
            f"The security team identified {severity_word} security event affecting "
            f"{hosts} host(s) and {users} account(s). "
            f"The activity is being investigated as {incident.get('title', 'a potential security incident').lower()}. "
            f"Current status: {incident.get('status')}. No claim of confirmed compromise is made until the "
            f"investigation is complete; this summary reflects automated detection, not a final determination."
        )

    def technical_summary(self, incident: dict) -> str:
        lines = [
            f"Incident ID: {incident.get('incident_id')}",
            f"Score: {incident.get('score')}/100 ({incident.get('severity')})",
            f"MITRE ATT&CK techniques: {', '.join(incident.get('mitre_techniques') or []) or 'none mapped'}",
            f"Affected hosts: {', '.join(incident.get('affected_hosts') or []) or 'none recorded'}",
            f"Affected accounts: {', '.join(incident.get('affected_users') or []) or 'none recorded'}",
            "",
            "Detection rules triggered:",
        ]
        for rule_id in incident.get("detection_ids") or []:
            lines.append(f"  - {rule_id}")
        return "\n".join(lines)
