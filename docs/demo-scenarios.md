# Demo Scenarios

All five scenarios are entirely synthetic, safe-by-design, and load
automatically from `data/scenarios/` on first launch (see
`Pipeline.load_demo_data`). None involve real malware, real credential
theft, real exploit code, or real data movement — every "attack" is a
handful of representative log records an analyst would plausibly see in
a real SIEM.

## Scenario A — Brute Force / Account Compromise

**File:** `scenario_a_bruteforce.json` (JSON)

`jdupont@WKS-14` receives 20 failed login attempts from a single external
IP in under two minutes, followed by a successful login, followed by an
administrative-activity event (the account added to a local
Administrators group).

**Expected result:** `RULE-AUTH-001` fires at CRITICAL — repeated
failures (+35), followed by success (+30), followed by privileged
activity (+20), on a base of 25.

## Scenario B — Suspicious PowerShell

**File:** `scenario_b_powershell.ndjson` (NDJSON)

`mvasseur@WKS-22` logs in normally, then PowerShell is launched with a
`-EncodedCommand` argument (a Base64-encoded download-and-execute
one-liner), followed by an outbound connection to an external IP on port
443, followed by `rundll32.exe` being spawned.

**Expected result:** `RULE-PS-001` fires at CRITICAL — encoded command
(+25), network connection follows (+25), external destination (+15),
suspicious child process (+15), on a base of 30.

## Scenario C — Persistence via Scheduled Task

**File:** `scenario_c_persistence.csv` (CSV)

An administrator logs into `SRV-APP03`, drops an executable into
`C:\Windows\Temp\`, then creates a scheduled task pointing at that
executable a couple of minutes later.

**Expected result:** `RULE-PERSIST-001` fires at HIGH — persistence
mechanism created (+20), preceded by admin/file-drop activity (+25),
privileged account (+10), on a base of 25.

## Scenario D — Lateral Movement

**File:** `scenario_d_lateral_movement.log` (plain text, key=value)

`jdupont`, already on `WKS-14`, authenticates remotely to a second host
(`10.0.30.12`) and a remote service is created shortly after
(`psexesvc.exe`-style activity).

**Expected result:** `RULE-LATERAL-001` fires — remote authentication
followed by remote service activity (+30), on a base of 30.

## Scenario E — Data Collection and Simulated Exfiltration

**File:** `scenario_e_exfiltration.json` (JSON)

`aharrison@SRV-FILE07` touches three sensitive files (finance, HR, legal)
over a few minutes, archives them into a single `.zip`, then an outbound
transfer event to an external IP follows. **No real file movement or
network transfer occurs anywhere in this project** — this is a static
log record representing what such activity would look like.

**Expected result:** `RULE-EXFIL-001` fires at CRITICAL — archive before
outbound transfer (+30), preceded by file collection (+15), external
destination (+20), on a base of 30.

## Benign baseline (used by the test suite, not loaded by the demo UI)

**File:** `tests/fixtures/benign_activity.json`

Two failed logins (below the brute-force threshold), a plain
non-encoded PowerShell one-liner, and a standalone scheduled task created
by an administrator with no preceding suspicious activity. This fixture
backs the false-positive-reduction tests in `tests/test_detection.py`:
plain PowerShell usage and a couple of mistyped passwords must never
produce a HIGH/CRITICAL detection.

## Walking through the demo (matches the project's acceptance criteria)

1. `python app.py`, open the UI — Overview shows 5 incidents, mostly
   CRITICAL/HIGH.
2. Open **Incidents**, click `INC-2026-0001` (Brute Force).
3. **Timeline** tab: see all 22 events in order.
4. **Raw Evidence** tab: inspect each underlying event, classify a few as
   CONFIRMED.
5. **Detections** tab: see the exact score breakdown and MITRE mapping.
6. **IOCs** tab: see the source IP tagged `ASSOCIATED_WITH_INCIDENT`.
7. **Attack Chain** tab: see the ATT&CK tactic/technique chain.
8. **AI Analysis** tab: read the generated executive/technical summaries.
9. **Analyst Notes** tab: add a note.
10. Change status to `INVESTIGATING`, then generate a report from the
    header button.
11. Go to **Settings**, upload a new synthetic log file, and watch the
    dashboard counts update immediately.
