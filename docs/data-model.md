# Data Model

All shapes are plain dataclasses in `src/soc_insight/models.py`.

## NormalizedEvent

The common internal event model every ingested log (regardless of source
format) is converted to.

```
event_id            stable, content-derived ID if the source has none
timestamp           parsed datetime (several ISO variants accepted)
event_type          e.g. "auth_failed_login", "process_powershell_execution"
host                optional
user                optional
source_ip           optional
destination_ip       optional
destination_port     optional
process              optional
command              optional
file                 optional
domain               optional
severity_hint        optional, as reported by the source (not authoritative)
raw                  the original record, kept for evidence display
metadata             free-form extra fields
source_format        json | ndjson | csv | log
source_file          originating filename
parse_warnings       non-fatal notes (e.g. "destination_port not numeric")
```

Field mapping is alias-based and tolerant (`ingestion/normalizer.py`):
e.g. `source_ip`, `src_ip`, `srcip`, and `client_ip` all map to
`source_ip`. A record missing a parseable timestamp or an event type
cannot be normalized and is reported as an `IngestionIssue` instead of
silently dropped or crashing the pipeline.

## IngestionIssue

```
source_file, line_number, reason, raw_fragment
```

Surfaced in the UI's Settings page and via `GET /api/ingestion-issues`.

## DetectionMatch

One instance of a rule firing against a window of correlated evidence.

```
rule_id, rule_name, description
severity                 derived from score, not asserted by the rule directly
base_confidence           the rule's base point value
mitre_technique
explanation               human-readable, evidence-specific
recommended_investigation list of next-step strings
evidence_event_ids         which NormalizedEvent IDs support this match
entity_key                 e.g. "host=WKS-14|user=jdupont"
score                      0-100
score_breakdown            [{"factor": ..., "points": ...}, ...]
window_start, window_end
```

## IOC

```
ioc_type      ipv4 | ipv6 | domain | url | hash_md5 | hash_sha1 |
              hash_sha256 | filename | username | hostname
value
first_seen, last_seen
related_event_ids
risk          OBSERVED | SUSPICIOUS | ASSOCIATED_WITH_INCIDENT
context       short notes on where/how it was seen
```

`risk` starts at `OBSERVED` for every extracted indicator, is upgraded to
`SUSPICIOUS` if it appears in the evidence of any scored detection, and
to `ASSOCIATED_WITH_INCIDENT` once that detection is grouped into an
incident. There is no fourth, stronger label — SOC-Insight never asserts
confirmed maliciousness on its own authority (see `docs/security.md`).

## Incident

```
incident_id            e.g. "INC-2026-0001"
title, created
severity, score
status                  NEW | INVESTIGATING | CONTAINED | RESOLVED | FALSE_POSITIVE
classification          UNRESOLVED | TRUE_POSITIVE | FALSE_POSITIVE | BENIGN_ACTIVITY
affected_hosts, affected_users, source_ips
ioc_values              ["ipv4:1.2.3.4", ...]
detection_ids           rule IDs involved
mitre_techniques
event_ids
timeline                [{"timestamp", "title", "event_id", "detail", "severity"}]
analyst_notes           [{"timestamp", "author", "note"}]
evidence_classifications {event_id: CONFIRMED|SUSPICIOUS|BENIGN|UNKNOWN}
```

Incidents are formed by grouping `DetectionMatch` objects that share an
`entity_key` and whose time windows are within one hour of each other
(`incidents/manager.py::_group_detections`) — this is what lets, e.g., a
brute-force detection and a subsequent privilege-escalation detection on
the same account become one incident instead of two.

## Why raw events are kept, not just parsed fields

`NormalizedEvent.raw` retains the original record. The UI's "Raw
Evidence" tab and the report generator can always fall back to what was
actually ingested, even for fields the normalizer doesn't recognize.
