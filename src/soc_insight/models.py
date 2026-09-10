"""
Core data models for SOC-Insight.

These are plain, dependency-free dataclasses. Everything downstream
(detection, correlation, scoring, reporting) operates on these shapes so the
data model stays consistent across the ingestion -> detection -> incident
pipeline described in docs/data-model.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Optional


SEVERITY_BANDS = [
    (0, 24, "INFO"),
    (25, 49, "LOW"),
    (50, 74, "MEDIUM"),
    (75, 89, "HIGH"),
    (90, 100, "CRITICAL"),
]


def severity_from_score(score: int) -> str:
    score = max(0, min(100, score))
    for lo, hi, label in SEVERITY_BANDS:
        if lo <= score <= hi:
            return label
    return "INFO"


@dataclass
class NormalizedEvent:
    """The common internal event model every ingested log is converted to."""

    event_id: str
    timestamp: datetime
    event_type: str  # e.g. "auth.failed_login", "process.creation"
    host: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    process: Optional[str] = None
    command: Optional[str] = None
    file: Optional[str] = None
    domain: Optional[str] = None
    severity_hint: Optional[str] = None  # raw severity as reported by source, if any
    raw: dict = field(default_factory=dict)  # original record, for evidence display
    metadata: dict = field(default_factory=dict)
    source_format: Optional[str] = None
    source_file: Optional[str] = None
    parse_warnings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d


@dataclass
class IngestionIssue:
    """A record that could not be fully parsed/normalized."""

    source_file: str
    line_number: Optional[int]
    reason: str
    raw_fragment: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DetectionMatch:
    """One instance of a detection rule firing against correlated evidence."""

    rule_id: str
    rule_name: str
    description: str
    severity: str
    base_confidence: int
    mitre_technique: str
    explanation: str
    recommended_investigation: list
    evidence_event_ids: list
    entity_key: str  # e.g. "host=WKS-14|user=jdupont"
    score: int = 0
    score_breakdown: list = field(default_factory=list)  # list of {factor, points}
    window_start: Optional[str] = None
    window_end: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IOC:
    ioc_type: str  # ipv4, ipv6, domain, url, hash_md5, hash_sha1, hash_sha256, filename, username, hostname
    value: str
    first_seen: str
    last_seen: str
    related_event_ids: list = field(default_factory=list)
    risk: str = "OBSERVED"  # OBSERVED, SUSPICIOUS, ASSOCIATED_WITH_INCIDENT
    context: list = field(default_factory=list)  # short notes on where it was seen

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TimelineEntry:
    timestamp: str
    title: str
    event_id: Optional[str]
    detail: str
    severity: str = "INFO"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Incident:
    incident_id: str
    title: str
    created: str
    severity: str
    score: int
    status: str  # NEW, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE
    classification: str  # UNRESOLVED, TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_ACTIVITY
    affected_hosts: list = field(default_factory=list)
    affected_users: list = field(default_factory=list)
    source_ips: list = field(default_factory=list)
    ioc_values: list = field(default_factory=list)  # references into IOC store
    detection_ids: list = field(default_factory=list)  # rule ids involved
    mitre_techniques: list = field(default_factory=list)
    event_ids: list = field(default_factory=list)
    timeline: list = field(default_factory=list)  # list of TimelineEntry dicts
    analyst_notes: list = field(default_factory=list)  # list of {timestamp, author, note}
    evidence_classifications: dict = field(default_factory=dict)  # event_id -> CONFIRMED/SUSPICIOUS/BENIGN/UNKNOWN
    scenario_tag: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)
