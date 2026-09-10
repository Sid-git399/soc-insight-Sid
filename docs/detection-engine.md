# Detection Engine

## Design goal

The detection engine must never be "keyword search wearing a SOC costume."
Every rule combines at least one of: event sequence, threshold, temporal
correlation, or entity correlation — and every rule must be able to answer
five questions for any match it produces (see `docs/data-model.md` for
the concrete fields these map to):

1. **WHAT** happened?
2. **WHY** was it detected?
3. **WHAT evidence** supports the detection?
4. **HOW severe** is it, and why?
5. **WHAT MITRE technique** is associated?

## Pipeline stages relevant to detection

```
NormalizedEvent[]
   -> build_entity_windows()      groups by host+user, splits on >20 min gaps
   -> for each window, for each Rule: rule.evaluate(window) -> RuleMatch[]
   -> score_match(base_points, factors) -> (score, severity, breakdown)
   -> DetectionMatch (rule metadata + evidence + score)
```

Correlation windows (`correlation/correlator.py`) are deliberately simple:
events for the same `host+user` pair are grouped, and a new window starts
whenever the gap since the previous event for that entity exceeds 20
minutes. This is enough to bind together a "burst" of related activity
(e.g. a brute-force attempt followed by a successful login two minutes
later) without conflating unrelated activity from the same user days
apart.

## Rule catalog

| Rule ID | Name | Base points | MITRE | Escalation factors |
|---|---|---|---|---|
| RULE-AUTH-001 | Brute Force / Account Compromise | 25 | T1110 | +20/35 repeated failures, +30 followed by success, +20 followed by privileged activity |
| RULE-AUTH-002 | Unusual Login Source or Time | 20 | T1078 | +15 unusual source/time flag, +15 external IP |
| RULE-PS-001 | Suspicious Encoded PowerShell | 30 | T1059.001 | +25 encoded command, +25 network connection follows, +15 external destination, +15 suspicious child process, +10 privileged account |
| RULE-PERSIST-001 | Persistence via Scheduled Task / Service | 25 | T1053.005 | +25 preceded by admin/file-drop activity, +10 privileged account |
| RULE-LATERAL-001 | Lateral Movement via Remote Services | 30 | T1021 | +15 privileged account |
| RULE-EXFIL-001 | Data Collection and Simulated Exfiltration | 30 | T1560 | +15 preceded by file collection, +20 external destination |
| RULE-PRIV-001 | Account or Privilege Manipulation | 20 | T1098 | +15 shortly after admin login |

Each rule is a small, independently testable Python function in
`src/soc_insight/detection/rules_data.py` (see `tests/test_detection.py`).
Adding a new rule means adding one `Rule(...)` entry to `ALL_RULES` — the
engine, scorer, API, and UI require no changes.

## Worked example (matches the project's scoring spec exactly)

> Base severity = 40
> + suspicious process = 15
> + encoded command = 15
> + privileged account = 10
> + external connection = 10
> **Final score = 90 -> CRITICAL**

This exact example is asserted in `tests/test_scoring.py::test_score_matches_documented_example`.

## False-positive resistance

Two rules are specifically designed to avoid over-triggering on benign
activity, and both are covered by tests in `tests/test_detection.py`:

- **RULE-PS-001** only fires at all when the PowerShell command line is
  *encoded/obfuscated*. A plain, readable PowerShell command (e.g.
  `Get-Process | Sort-Object CPU`) never triggers this rule, regardless
  of how the process was launched.
- **RULE-AUTH-001** requires at least 5 failed logins in one correlation
  window before it fires at all; 1–4 failed logins (a typical mistyped
  password) produce no detection.
- **RULE-PERSIST-001** still fires on a standalone scheduled task (per
  the project's own scoring philosophy — "scheduled task alone: MEDIUM"),
  but stays in the LOW/MEDIUM band unless it is preceded by suspicious
  administrative or file-drop activity, which is what pushes it to HIGH.

## Explainability in the UI

Every `DetectionMatch` carries a `score_breakdown` list of
`{"factor": <human-readable label>, "points": <int>}` — this is rendered
verbatim in the Incident Investigation -> Detections tab. There is no
separate "confidence" number computed by a black box; the score *is* the
explanation.
