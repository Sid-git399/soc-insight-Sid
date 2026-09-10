"""
IOC extraction.

Extracts candidate indicators (IPs, domains, URLs, hashes, filenames,
usernames, hostnames) from normalized events. SOC-Insight never claims an
IOC is confirmed-malicious on its own authority -- risk labels are limited
to "OBSERVED", "SUSPICIOUS" (appeared in evidence tied to a scored
detection), and "ASSOCIATED_WITH_INCIDENT" (tied to a created incident).
There is no external threat-intel reputation lookup.
"""
from __future__ import annotations

import ipaddress
import re

from soc_insight.models import IOC, NormalizedEvent

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
URL_RE = re.compile(r"\bhttps?://[^\s\"']+", re.IGNORECASE)
HASH_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
HASH_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
HASH_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _valid_ipv6(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except ValueError:
        return False


def _candidates_from_text(text: str) -> list[tuple[str, str]]:
    """Returns (ioc_type, value) pairs found in a text blob."""
    found = []
    for m in URL_RE.findall(text):
        found.append(("url", m))
    for m in HASH_SHA256_RE.findall(text):
        found.append(("hash_sha256", m.lower()))
    for m in HASH_SHA1_RE.findall(text):
        found.append(("hash_sha1", m.lower()))
    for m in HASH_MD5_RE.findall(text):
        found.append(("hash_md5", m.lower()))
    for m in IPV6_RE.findall(text):
        if _valid_ipv6(m):
            found.append(("ipv6", m))
    for m in IPV4_RE.findall(text):
        if _valid_ipv4(m):
            found.append(("ipv4", m))
    for m in DOMAIN_RE.findall(text):
        if not _valid_ipv4(m):
            found.append(("domain", m.lower()))
    return found


def extract_iocs(events: list) -> list:
    """
    Returns a list of IOC objects, deduplicated by (type, value), each
    carrying first/last seen timestamps and the events it was observed in.
    """
    store: dict[tuple[str, str], IOC] = {}

    def record(ioc_type: str, value: str, event: NormalizedEvent, context: str):
        key = (ioc_type, value)
        ts = event.timestamp.isoformat()
        if key not in store:
            store[key] = IOC(
                ioc_type=ioc_type,
                value=value,
                first_seen=ts,
                last_seen=ts,
                related_event_ids=[event.event_id],
                context=[context],
            )
        else:
            ioc = store[key]
            if ts < ioc.first_seen:
                ioc.first_seen = ts
            if ts > ioc.last_seen:
                ioc.last_seen = ts
            if event.event_id not in ioc.related_event_ids:
                ioc.related_event_ids.append(event.event_id)
            if context not in ioc.context:
                ioc.context.append(context)

    for event in events:
        if event.source_ip and (_valid_ipv4(event.source_ip) or _valid_ipv6(event.source_ip)):
            ioc_type = "ipv4" if _valid_ipv4(event.source_ip) else "ipv6"
            record(ioc_type, event.source_ip, event, "source IP of an event")
        if event.destination_ip and (_valid_ipv4(event.destination_ip) or _valid_ipv6(event.destination_ip)):
            ioc_type = "ipv4" if _valid_ipv4(event.destination_ip) else "ipv6"
            record(ioc_type, event.destination_ip, event, "destination IP of an event")
        if event.domain:
            record("domain", event.domain.lower(), event, "DNS query / domain field")
        if event.file:
            record("filename", event.file, event, "file referenced by an event")
            for ioc_type, value in _candidates_from_text(event.file):
                if ioc_type != "domain":  # avoid misclassifying filenames with dots as domains
                    record(ioc_type, value, event, "extracted from file field")
        if event.user:
            record("username", event.user, event, "account referenced by an event")
        if event.host:
            record("hostname", event.host, event, "host referenced by an event")
        if event.command:
            for ioc_type, value in _candidates_from_text(event.command):
                record(ioc_type, value, event, "extracted from command line")

    return list(store.values())


def apply_detection_risk(iocs: list, detections: list) -> None:
    """
    Upgrades IOC risk labels from OBSERVED to SUSPICIOUS when the IOC's
    related events overlap with a scored detection's evidence.
    """
    evidence_event_ids: set = set()
    for d in detections:
        evidence_event_ids.update(d.evidence_event_ids)

    for ioc in iocs:
        if evidence_event_ids.intersection(ioc.related_event_ids):
            ioc.risk = "SUSPICIOUS"
