# SOC-Insight

**AI-assisted security investigation & threat hunting workbench.**

SOC-Insight is a local, self-contained lab that simulates the core workflow
of a SOC (Security Operations Center) analyst: take raw security events,
correlate them, detect suspicious behavior with explainable rules, score
risk transparently, extract indicators of compromise, map behavior to
MITRE ATT&CK, build an incident timeline, and produce a professional
incident report — all without depending on a paid external API.

This is an educational / portfolio security lab, not a production SIEM,
antivirus, EDR, or SOC replacement. See [Limitations](#limitations) below.

---

## Table of contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Dataset description](#dataset-description)
- [Detection engine](#detection-engine)
- [Scoring methodology](#scoring-methodology)
- [MITRE ATT&CK integration](#mitre-attck-integration)
- [Security considerations](#security-considerations)
- [Testing](#testing)
- [Limitations](#limitations)
- [Future improvements](#future-improvements)

---

## Overview

The pipeline follows one direction, matching the mental model of an actual
SOC:

```
RAW SECURITY DATA
   -> INGESTION            (json / ndjson / csv / text log)
   -> NORMALIZATION        (common internal event model)
   -> EVENT CORRELATION    (per-entity time windows)
   -> DETECTION ENGINE     (modular, explainable rules)
   -> RISK SCORING         (transparent, additive, auditable)
   -> IOC EXTRACTION       (IPs, domains, hashes, files, accounts, hosts)
   -> MITRE ATT&CK MAPPING (local technique dataset)
   -> INCIDENT TIMELINE    (grouped, chronological)
   -> ANALYST INVESTIGATION (status, classification, notes, evidence tags)
   -> FINAL INCIDENT REPORT
```

Every stage is a plain Python module with no hidden magic: the same code
path backs both the CLI (`main.py`) and the web UI (`app.py`).

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full breakdown.
In short:

```
src/soc_insight/
  models.py        - shared dataclasses (event, detection, IOC, incident)
  ingestion/        - safe parsers (json/ndjson/csv/log) + normalization
  correlation/      - per-entity, per-time-window grouping
  detection/        - rule catalog + engine (the detection logic)
  scoring/          - transparent, auditable risk scoring
  ioc/              - indicator extraction
  mitre/            - local MITRE ATT&CK technique dataset
  incidents/        - incident grouping, timelines, attack-chain ordering
  hunting/          - safe threat-hunting query language
  analysis/         - pluggable AI-assisted analysis (local by default)
  reports/          - incident report generation
  pipeline.py       - orchestrates all of the above

app.py              - Flask API + static frontend server
main.py             - CLI entry point
frontend/           - dark, dense investigation UI (vanilla HTML/CSS/JS)
data/scenarios/     - bundled synthetic attack scenarios
tests/              - pytest suite
docs/               - architecture, detection engine, data model, security, demo scenarios
```

Detection logic is never embedded in the UI layer; the frontend only calls
the JSON API in `app.py`, which in turn only calls `pipeline.py`.

## Features

- Multi-format ingestion (JSON, NDJSON, CSV, plain-text key=value logs)
- Tolerant normalization with reported (never crashing) parse issues
- Entity + time-window correlation
- 7 modular, independently testable detection rules covering brute force /
  account compromise, unusual logins, encoded PowerShell, persistence,
  lateral movement, data collection / exfiltration, and account
  manipulation
- Fully transparent, additive risk scoring with a visible breakdown per
  detection (no black-box "AI confidence" number)
- IOC extraction with honest risk labeling (`OBSERVED` / `SUSPICIOUS` /
  `ASSOCIATED_WITH_INCIDENT` — never a claim of confirmed malice)
- Local MITRE ATT&CK dataset scoped to what the rules can actually detect
- Incident management with status, classification, analyst notes, and
  per-evidence classification (CONFIRMED / SUSPICIOUS / BENIGN / UNKNOWN)
- Safe threat-hunting query language (`field = "value"`, `contains`,
  `AND` / `OR` — no `eval`, no injection path)
- AI-assisted analysis layer (incident summary, evidence explanations,
  investigation suggestions, executive & technical summaries) built on a
  pluggable `AIProvider` interface; the default implementation is
  template-based and requires no external API
- Professional Markdown incident report generation
- Dark, dense, professional investigation UI: Overview, Incidents,
  Incident Investigation, Event Explorer, Threat Hunting, Detection
  Rules, MITRE ATT&CK, IOC Explorer, Reports, Settings
- Upload your own synthetic log file and re-run the whole pipeline live

## Installation

Requires Python 3.10+.

```bash
cd soc-insight
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

### Web UI

```bash
python app.py
```

Then open **http://127.0.0.1:5000**. The demo environment (5 synthetic
incidents) loads automatically on first launch.

### CLI

```bash
# Load the bundled demo scenarios and print a summary
python main.py demo

# Ingest your own log file(s) and run detection
python main.py ingest path/to/your_logs.json path/to/more_logs.csv

# Generate a text report for a specific incident
python main.py report INC-2026-0001
```

### Importing your own data

From the **Settings** page in the UI, or via `POST /api/ingest`
(multipart form field `file`), you can upload a `.json`, `.ndjson`,
`.csv`, or `.log`/`.txt` file. It is parsed with the same safe parsers as
the bundled data, normalized, and immediately run through the full
detection pipeline. Files are capped at 10 MB and are always treated as
inert data — nothing in a log file is ever executed.

## Dataset description

Five safe, coherent, synthetic attack scenarios ship in `data/scenarios/`,
one per required format family (see
[`docs/demo-scenarios.md`](docs/demo-scenarios.md) for the full narrative
of each):

| File | Format | Scenario |
|---|---|---|
| `scenario_a_bruteforce.json` | JSON | Brute force -> account compromise |
| `scenario_b_powershell.ndjson` | NDJSON | Encoded PowerShell -> C2-style connection |
| `scenario_c_persistence.csv` | CSV | Executable drop -> scheduled task persistence |
| `scenario_d_lateral_movement.log` | text log | Remote auth -> remote service execution |
| `scenario_e_exfiltration.json` | JSON | File collection -> archive -> simulated outbound transfer |

All data is fabricated. IPs used to represent "external" infrastructure
are arbitrary, non-attributable addresses chosen only to be outside
private/reserved ranges; no real organization or individual is
represented.

## Detection engine

See [`docs/detection-engine.md`](docs/detection-engine.md). Rules combine
individual event signatures, thresholds, and temporal/entity correlation
rather than keyword matching alone — e.g. 5 failed logins alone score low,
but 20 failed logins followed by a successful login and privileged
activity score CRITICAL.

## Scoring methodology

`score = base_points_for_the_rule + sum(evidence_factor_points)`, clamped
to `[0, 100]`, mapped to a severity band:

| Score | Severity |
|---|---|
| 0–24 | INFO |
| 25–49 | LOW |
| 50–74 | MEDIUM |
| 75–89 | HIGH |
| 90–100 | CRITICAL |

Every point in the breakdown is labeled and shown in the UI's Detections
tab — there is no hidden or unexplainable component.

## MITRE ATT&CK integration

A small, local dataset (`src/soc_insight/mitre/dataset.py`) covers only
the techniques the bundled rules can produce evidence for (see
`docs/detection-engine.md` for the full rule -> technique table). No
external ATT&CK service is called.

## Security considerations

See [`docs/security.md`](docs/security.md) for the full write-up.
Highlights: uploaded logs are always treated as data, never executed;
strict file size and record-count caps; safe JSON/CSV parsing via the
standard library only; a small, `eval`-free threat-hunting query
grammar; no secrets or API keys anywhere in the codebase; environment
variables for the one optional integration point (a local model
endpoint).

## Testing

```bash
pip install -r requirements.txt
pytest
```

The suite (60+ tests) covers parsing/malformed input, detection rules
(including explicit false-positive-reduction cases), scoring, IOC
extraction, MITRE mapping, incident creation, threat-hunting search,
report generation, and security-relevant behavior (size limits, no
code execution, no query-injection path).

## Limitations

SOC-Insight is a **security laboratory / educational system**. It is
explicitly **not**:

- a production SIEM
- an antivirus product
- an EDR (Endpoint Detection and Response) agent
- a malware scanner
- a replacement for a real SOC or a licensed security professional

State is in-memory only (a restart clears everything except the bundled
demo data); there is no authentication, multi-user support, or
persistent database, because this is a single-analyst local lab, not a
deployable product. Detection rules are intentionally few and are scoped
to the bundled scenarios rather than aiming for broad real-world
coverage. IOC "risk" labels reflect only what the local rules observed —
there is no external threat-intelligence reputation lookup.

## Future improvements

- Persistent storage (SQLite) so incidents survive a restart
- Additional detection rules (DNS tunneling, credential dumping signatures, etc.)
- A pluggable rule-definition format (YAML/JSON) so rules can be added
  without editing Python
- Multi-analyst support with per-user attribution on notes/status changes
- A real local-model integration example (e.g. a small local LLM server)
  for richer narrative generation
