# Architecture

## Layering

SOC-Insight is deliberately a plain, layered Python application rather
than a set of microservices — the project brief explicitly calls for
avoiding overengineering, and a local single-analyst lab has no need for
network boundaries between its own modules.

```
                     ┌─────────────────────────┐
                     │   frontend/ (HTML/JS)   │   <- no detection logic
                     └────────────┬────────────┘
                                  │ fetch() JSON
                     ┌────────────▼────────────┐
                     │   app.py (Flask API)    │   <- thin: validates input,
                     └────────────┬────────────┘      calls pipeline, serializes
                                  │
                     ┌────────────▼────────────┐
                     │  pipeline.py            │   <- orchestration only
                     └───┬───┬───┬───┬───┬────┬┘
                         │   │   │   │   │    │
                 ingestion detection correlation scoring ioc incidents ...
```

`main.py` (the CLI) and `app.py` (the web server) are two thin front
doors onto the exact same `Pipeline` object graph — neither contains
detection or scoring logic itself.

## Module responsibilities

| Module | Responsibility | Explicitly does NOT do |
|---|---|---|
| `ingestion/parsers.py` | Turn raw bytes (json/ndjson/csv/text-log) into plain dicts, safely | Interpret field meaning, execute anything |
| `ingestion/normalizer.py` | Map raw dicts onto `NormalizedEvent`, tolerating missing fields | Detection logic |
| `correlation/correlator.py` | Group events into per-entity, per-time-window buckets | Decide what's suspicious |
| `detection/rules_data.py` | Define detection rules and their `evaluate()` logic | Compute a final score |
| `detection/engine.py` | Run every rule against every window | Contain rule-specific heuristics |
| `scoring/scorer.py` | Turn (base points + evidence factors) into a score + severity | Decide *which* factors apply |
| `ioc/extractor.py` | Extract candidate indicators from event fields | Claim external threat-intel reputation |
| `mitre/dataset.py` | Local technique metadata | Call any external ATT&CK service |
| `incidents/manager.py` | Group detections into incidents, build timelines | Detection logic |
| `hunting/search.py` | Parse/evaluate a small, safe query grammar | Anything resembling `eval` |
| `analysis/*` | Produce narrative text from incident data | Require an external paid API |
| `reports/generator.py` | Assemble the structured incident report | Generate binary output (kept as Markdown/text by design) |

## Why this structure

- **Testability.** Every stage takes plain data in and returns plain data
  out, so each layer has focused unit tests (see `tests/`) without
  needing a running server or a database.
- **Explainability by construction.** Because `DetectionMatch` always
  carries `explanation`, `score_breakdown`, `mitre_technique`, and
  `recommended_investigation`, the UI and the report generator never have
  to *invent* justification after the fact — they just render what the
  engine already produced.
- **No framework lock-in for the core logic.** `soc_insight/` has zero
  Flask imports. It could be wrapped in a different web framework, a
  Jupyter notebook, or a batch script without changes.

## Data flow for one request (example: viewing an incident)

1. Browser calls `GET /api/incidents/INC-2026-0001`.
2. `app.py` looks up the `Incident` object in the running `Pipeline`.
3. `pipeline.incident_to_dict()` enriches the incident with its
   originating `DetectionMatch` objects (for score breakdowns) and its
   MITRE attack-chain ordering.
4. Flask serializes the result to JSON.
5. `frontend/app.js` renders the Timeline / Evidence / Detections / IOCs /
   Attack Chain / AI Analysis / Notes tabs from that one JSON payload.

## State model

State is a single in-memory `Pipeline` instance per server process:
events, ingestion issues, detections, incidents, and IOCs. This matches
the project's scope (a local lab, not a multi-tenant service). Restarting
`app.py` reloads the bundled demo scenarios from disk; anything
ingested via upload or via `main.py ingest` in a previous run is not
persisted (see `docs/security.md` and the README's Limitations section).
