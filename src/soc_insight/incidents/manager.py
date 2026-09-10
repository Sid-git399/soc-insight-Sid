"""
Incident management.

Groups scored DetectionMatch objects that share an entity (host+user) and
overlap in time into a single Incident, builds a human-readable timeline
from the underlying evidence events, and tracks the analyst-facing
lifecycle (status + classification) described in docs/data-model.md.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from soc_insight.mitre import get_technique
from soc_insight.models import DetectionMatch, Incident, NormalizedEvent, TimelineEntry


def _titles_for_rule(rule_id: str) -> str:
    return {
        "RULE-AUTH-001": "Brute Force / Account Compromise",
        "RULE-AUTH-002": "Unusual Authentication Activity",
        "RULE-PS-001": "Suspicious PowerShell Execution",
        "RULE-PERSIST-001": "Persistence Mechanism Established",
        "RULE-LATERAL-001": "Lateral Movement Activity",
        "RULE-EXFIL-001": "Data Collection and Simulated Exfiltration",
        "RULE-PRIV-001": "Account or Privilege Manipulation",
    }.get(rule_id, rule_id)


class IncidentIdAllocator:
    def __init__(self, year: Optional[int] = None, start_at: int = 1):
        self.year = year or datetime.now(timezone.utc).year
        self._counter = start_at

    def next_id(self) -> str:
        incident_id = f"INC-{self.year}-{self._counter:04d}"
        self._counter += 1
        return incident_id


def _group_detections(detections: list) -> list[list[DetectionMatch]]:
    """Groups detections sharing an entity_key whose windows overlap or are adjacent."""
    by_entity: dict[str, list[DetectionMatch]] = {}
    for d in detections:
        by_entity.setdefault(d.entity_key, []).append(d)

    groups: list[list[DetectionMatch]] = []
    for entity_key, dets in by_entity.items():
        dets.sort(key=lambda d: d.window_start or "")
        current: list[DetectionMatch] = []
        current_end = None
        for d in dets:
            start = datetime.fromisoformat(d.window_start) if d.window_start else None
            if current and current_end and start and (start - current_end).total_seconds() > 3600:
                groups.append(current)
                current = []
            current.append(d)
            end = datetime.fromisoformat(d.window_end) if d.window_end else start
            if end and (current_end is None or end > current_end):
                current_end = end
        if current:
            groups.append(current)
    return groups


def build_timeline(events_by_id: dict, group: list) -> list:
    event_ids = sorted({eid for d in group for eid in d.evidence_event_ids})
    tl_events = [events_by_id[eid] for eid in event_ids if eid in events_by_id]
    tl_events.sort(key=lambda e: e.timestamp)

    entries = []
    for e in tl_events:
        title = e.event_type.replace("_", " ").replace(".", " ").title()
        detail_parts = []
        if e.user:
            detail_parts.append(f"user={e.user}")
        if e.host:
            detail_parts.append(f"host={e.host}")
        if e.process:
            detail_parts.append(f"process={e.process}")
        if e.source_ip:
            detail_parts.append(f"source_ip={e.source_ip}")
        if e.destination_ip:
            dst = e.destination_ip
            if e.destination_port:
                dst += f":{e.destination_port}"
            detail_parts.append(f"destination={dst}")
        if e.file:
            detail_parts.append(f"file={e.file}")
        entries.append(
            TimelineEntry(
                timestamp=e.timestamp.isoformat(),
                title=title,
                event_id=e.event_id,
                detail=", ".join(detail_parts),
            ).to_dict()
        )
    return entries


def build_incidents(
    events: list,
    detections: list,
    allocator: Optional[IncidentIdAllocator] = None,
) -> list:
    allocator = allocator or IncidentIdAllocator()
    events_by_id = {e.event_id: e for e in events}

    incidents: list[Incident] = []
    for group in _group_detections(detections):
        group.sort(key=lambda d: d.score, reverse=True)
        top = group[0]
        event_ids = sorted({eid for d in group for eid in d.evidence_event_ids})
        tl_events = [events_by_id[eid] for eid in event_ids if eid in events_by_id]

        hosts = sorted({e.host for e in tl_events if e.host})
        users = sorted({e.user for e in tl_events if e.user})
        source_ips = sorted({e.source_ip for e in tl_events if e.source_ip})
        mitre_techniques = sorted({d.mitre_technique for d in group})
        rule_ids = sorted({d.rule_id for d in group})

        overall_score = max(d.score for d in group)
        from soc_insight.models import severity_from_score
        severity = severity_from_score(overall_score)

        title = _titles_for_rule(top.rule_id)
        if len(group) > 1:
            title += f" (+{len(group) - 1} related detection{'s' if len(group) > 2 else ''})"

        incident = Incident(
            incident_id=allocator.next_id(),
            title=title,
            created=min(e.timestamp for e in tl_events).isoformat() if tl_events else "",
            severity=severity,
            score=overall_score,
            status="NEW",
            classification="UNRESOLVED",
            affected_hosts=hosts,
            affected_users=users,
            source_ips=source_ips,
            detection_ids=rule_ids,
            mitre_techniques=mitre_techniques,
            event_ids=event_ids,
            timeline=build_timeline(events_by_id, group),
        )
        incidents.append(incident)

    incidents.sort(key=lambda i: i.score, reverse=True)
    return incidents


def attack_chain(incident: Incident) -> list:
    """
    Produces an ordered [{tactic, technique_id, technique_name}] chain for
    the incident's MITRE techniques, ordered by kill-chain phase rather
    than by discovery order, for the attack-chain visualization.
    """
    TACTIC_ORDER = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Command and Control", "Exfiltration", "Impact",
    ]

    def sort_key(tid: str) -> int:
        tech = get_technique(tid)
        if not tech:
            return len(TACTIC_ORDER)
        tactic_first = tech["tactic"].split("/")[0].strip()
        return TACTIC_ORDER.index(tactic_first) if tactic_first in TACTIC_ORDER else len(TACTIC_ORDER)

    chain = []
    for tid in sorted(incident.mitre_techniques, key=sort_key):
        tech = get_technique(tid)
        if tech:
            chain.append({
                "tactic": tech["tactic"].split("/")[0].strip(),
                "technique_id": tid,
                "technique_name": tech["name"],
            })
    return chain
