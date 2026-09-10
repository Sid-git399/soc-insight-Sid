"""
Incident report generation.

Produces a Markdown report following the structure requested for
SOC-Insight: header, executive summary, classification, affected assets,
timeline, detection evidence, IOCs, MITRE mapping, analyst findings,
recommended actions, and final classification. The report is generated
entirely from data already on the incident (plus the pluggable analysis
layer for the narrative sections) -- no external service is called.
"""
from __future__ import annotations

from datetime import datetime, timezone

from soc_insight.analysis import get_default_provider
from soc_insight.mitre import get_technique


def _iocs_for_incident(incident: dict, all_iocs: list) -> list:
    event_ids = set(incident.get("event_ids", []))
    return [ioc for ioc in all_iocs if event_ids.intersection(ioc.get("related_event_ids", []))]


def generate_report(incident: dict, all_iocs: list, provider=None) -> str:
    provider = provider or get_default_provider()
    incident = dict(incident)
    incident["_recommended_investigation"] = incident.get("_recommended_investigation", [])

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    iocs = _iocs_for_incident(incident, all_iocs)

    lines = []
    lines.append("SOC-INSIGHT INCIDENT REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated: {generated_at}")
    lines.append("Environment: Simulation / lab (synthetic data)")
    lines.append("")
    lines.append(f"Incident ID: {incident.get('incident_id')}")
    lines.append(f"Title: {incident.get('title')}")
    lines.append(f"Created: {incident.get('created')}")
    lines.append(f"Status: {incident.get('status')}")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append(provider.executive_summary(incident))
    lines.append("")

    lines.append("## Incident Classification")
    lines.append(f"Classification: {incident.get('classification')}")
    lines.append(f"Severity: {incident.get('severity')}  (risk score {incident.get('score')}/100)")
    lines.append("")

    lines.append("## Affected Assets")
    lines.append(f"Hosts: {', '.join(incident.get('affected_hosts') or []) or 'none recorded'}")
    lines.append(f"Accounts: {', '.join(incident.get('affected_users') or []) or 'none recorded'}")
    lines.append(f"Source IPs: {', '.join(incident.get('source_ips') or []) or 'none recorded'}")
    lines.append("")

    lines.append("## Timeline")
    for entry in incident.get("timeline", []):
        lines.append(f"  {entry.get('timestamp')}  {entry.get('title')} — {entry.get('detail')}")
    if not incident.get("timeline"):
        lines.append("  No timeline events recorded.")
    lines.append("")

    lines.append("## Detection Evidence")
    lines.append(provider.summarize_incident(incident))
    lines.append(f"Detection rules triggered: {', '.join(incident.get('detection_ids') or []) or 'none'}")
    lines.append("")

    lines.append("## Indicators of Compromise")
    if iocs:
        for ioc in iocs:
            lines.append(f"  [{ioc.get('ioc_type')}] {ioc.get('value')}  (risk: {ioc.get('risk')}, first seen {ioc.get('first_seen')})")
    else:
        lines.append("  No indicators of compromise extracted for this incident.")
    lines.append("")

    lines.append("## MITRE ATT&CK Mapping")
    for tid in incident.get("mitre_techniques") or []:
        tech = get_technique(tid)
        if tech:
            lines.append(f"  {tech['tactic']} -> {tech['name']} ({tid})")
    if not incident.get("mitre_techniques"):
        lines.append("  No techniques mapped.")
    lines.append("")

    lines.append("## Analyst Findings")
    notes = incident.get("analyst_notes") or []
    if notes:
        for note in notes:
            lines.append(f"  [{note.get('timestamp')}] {note.get('author', 'analyst')}: {note.get('note')}")
    else:
        lines.append("  No analyst notes recorded yet.")
    lines.append("")

    lines.append("## Recommended Actions")
    for suggestion in provider.investigation_suggestions(incident):
        lines.append(f"  - {suggestion}")
    lines.append("")

    lines.append("## Final Classification")
    lines.append(f"  {incident.get('classification')} (status: {incident.get('status')})")
    lines.append("")
    lines.append("-" * 60)
    lines.append(
        "This report was produced by SOC-Insight, an educational SOC "
        "investigation lab. It is based on synthetic/simulated data and "
        "rule-based detection logic, not a production security decision."
    )

    return "\n".join(lines)
