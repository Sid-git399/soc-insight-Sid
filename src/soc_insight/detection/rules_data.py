"""
Detection rule catalog.

Each Rule is a self-contained, independently testable unit: metadata
(id, name, severity, MITRE technique, investigation guidance) plus an
`evaluate(window)` function that inspects one EntityWindow and returns zero
or more RuleMatch objects. New rules can be added here without touching the
engine, the scorer, or the UI.

Rules deliberately return *evidence factors* (see signals.py) rather than a
final score -- scoring/scorer.py is the single place that turns evidence
into a number, so the scoring logic stays auditable in one file.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from soc_insight.correlation import EntityWindow
from soc_insight.detection import signals as sig


@dataclass
class RuleMatch:
    evidence_event_ids: list
    factors: list  # list of (label, points)
    explanation: str
    window_start: str
    window_end: str


@dataclass
class Rule:
    rule_id: str
    name: str
    description: str
    base_points: int
    mitre_technique: str
    recommended_investigation: list
    evaluate: "callable" = field(repr=False, compare=False)


def _span(events) -> tuple[str, str]:
    ts = sorted(e.timestamp for e in events)
    return ts[0].isoformat(), ts[-1].isoformat()


# ---------------------------------------------------------------------------
# Scenario A -- Brute force / account compromise
# ---------------------------------------------------------------------------

FAILED_LOGIN_THRESHOLD_LOW = 5
FAILED_LOGIN_THRESHOLD_HIGH = 15


def _eval_brute_force(window: EntityWindow) -> list[RuleMatch]:
    failed = [e for e in window.events if sig.event_type_matches(e, "failed_login", "auth.failed", "login_failed")]
    success = [e for e in window.events if sig.event_type_matches(e, "successful_login", "auth.success", "login_success")]

    if len(failed) < FAILED_LOGIN_THRESHOLD_LOW:
        return []

    factors = [("repeated failed authentication", 20 if len(failed) < FAILED_LOGIN_THRESHOLD_HIGH else 35)]
    evidence = list(failed)
    explanation = f"{len(failed)} failed authentication attempts observed for this account/host within the correlation window."

    following_success = [e for e in success if e.timestamp > failed[-1].timestamp - timedelta(minutes=2)]
    if following_success:
        factors.append(("failed attempts followed by a successful authentication", 30))
        evidence += following_success
        explanation += f" A successful authentication followed at {following_success[0].timestamp.isoformat()}, consistent with a compromised credential."
        admin_follow_up = [
            e for e in window.events
            if e.timestamp >= following_success[0].timestamp
            and sig.event_type_matches(e, "admin", "privilege", "group_membership")
        ]
        if admin_follow_up:
            factors.append(("privileged/administrative activity after the successful login", 20))
            evidence += admin_follow_up
            explanation += " Privileged activity was then observed on the same account, escalating this from a login anomaly to a likely account compromise."

    start, end = _span(evidence)
    return [RuleMatch(sorted({e.event_id for e in evidence}), factors, explanation, start, end)]


RULE_BRUTE_FORCE = Rule(
    rule_id="RULE-AUTH-001",
    name="Brute Force / Account Compromise",
    description="Detects repeated failed authentication attempts, optionally followed by a successful login and privileged activity on the same account.",
    base_points=25,
    mitre_technique="T1110",
    recommended_investigation=[
        "Confirm whether the account owner attempted these logins.",
        "Check the source IP/host reputation and recent activity.",
        "Review what the account did immediately after the successful login.",
        "Consider forcing a password reset and reviewing MFA status for the account.",
    ],
    evaluate=_eval_brute_force,
)


def _eval_unusual_login_source(window: EntityWindow) -> list[RuleMatch]:
    logins = [e for e in window.events if sig.event_type_matches(e, "login", "auth")]
    flagged = [e for e in logins if sig.event_type_matches(e, "unusual_source", "unusual_login", "unusual_time")]
    if not flagged:
        return []
    factors = [("authentication flagged as unusual by source telemetry", 15)]
    if any(sig.is_external_ip(e.source_ip) for e in flagged):
        factors.append(("originating from an external IP address", 15))
    start, end = _span(flagged)
    explanation = "Authentication activity was tagged as occurring from an unusual source or at an unusual time relative to this account's normal pattern."
    return [RuleMatch(sorted({e.event_id for e in flagged}), factors, explanation, start, end)]


RULE_UNUSUAL_LOGIN = Rule(
    rule_id="RULE-AUTH-002",
    name="Unusual Login Source or Time",
    description="Flags authentication events explicitly tagged by the source telemetry as occurring from an unusual location or at an unusual time.",
    base_points=20,
    mitre_technique="T1078",
    recommended_investigation=[
        "Verify the login against the user's known travel/remote-work pattern.",
        "Check whether the source IP is a known corporate VPN egress point.",
    ],
    evaluate=_eval_unusual_login_source,
)


# ---------------------------------------------------------------------------
# Scenario B -- Suspicious PowerShell / command execution
# ---------------------------------------------------------------------------

def _eval_powershell(window: EntityWindow) -> list[RuleMatch]:
    ps_events = [e for e in window.events if sig.is_powershell(e.process) or sig.event_type_matches(e, "powershell")]
    if not ps_events:
        return []

    encoded = [e for e in ps_events if sig.has_encoded_command(e.command)]
    if not encoded:
        return []  # plain PowerShell use alone is not actionable enough to raise an incident

    factors = [("encoded/obfuscated PowerShell command", 25)]
    evidence = list(encoded)
    explanation = "PowerShell was executed with an encoded or obfuscated command line, a common technique to hide the true command from casual log review."

    network = [
        e for e in window.events
        if e.timestamp >= encoded[0].timestamp
        and sig.event_type_matches(e, "network", "connection", "dns")
    ]
    if network:
        factors.append(("network connection shortly after the encoded command", 25))
        evidence += network
        explanation += " A network connection followed shortly after, consistent with command-and-control or payload retrieval."
        if any(sig.is_external_ip(e.destination_ip) for e in network):
            factors.append(("connection destination is an external IP address", 15))

    child = [
        e for e in window.events
        if e.timestamp >= encoded[0].timestamp
        and sig.event_type_matches(e, "process")
        and e.process and e.process.lower() not in {"powershell.exe", "powershell"}
        and sig.is_suspicious_process(e.process)
    ]
    if child:
        factors.append(("suspicious child process spawned after PowerShell", 15))
        evidence += child
        explanation += " PowerShell then spawned an additional suspicious process."

    if sig.is_privileged_account(window.user):
        factors.append(("privileged account context", 10))

    start, end = _span(evidence)
    return [RuleMatch(sorted({e.event_id for e in evidence}), factors, explanation, start, end)]


RULE_POWERSHELL = Rule(
    rule_id="RULE-PS-001",
    name="Suspicious Encoded PowerShell",
    description="Detects PowerShell execution using encoded/obfuscated commands, escalating severity when followed by network activity or a suspicious child process.",
    base_points=30,
    mitre_technique="T1059.001",
    recommended_investigation=[
        "Decode and review the PowerShell command line content.",
        "Identify the parent process that launched PowerShell.",
        "Inspect any outbound connections made during or after execution.",
        "Check whether this matches an approved administrative script.",
    ],
    evaluate=_eval_powershell,
)


# ---------------------------------------------------------------------------
# Scenario C -- Persistence via scheduled task
# ---------------------------------------------------------------------------

def _eval_persistence(window: EntityWindow) -> list[RuleMatch]:
    tasks = [e for e in window.events if sig.event_type_matches(e, "scheduled_task", "service_creation", "startup_modification")]
    if not tasks:
        return []

    factors = [("persistence mechanism created (scheduled task/service/startup entry)", 20)]
    evidence = list(tasks)
    explanation = "A scheduled task, service, or startup modification was created, which is a common persistence mechanism."

    admin_activity = [
        e for e in window.events
        if e.timestamp <= tasks[0].timestamp
        and sig.event_type_matches(e, "admin", "privilege", "executable_dropped", "file_creation")
    ]
    if admin_activity:
        factors.append(("preceded by administrative or file-drop activity on the same host", 25))
        evidence += admin_activity
        explanation += " This followed administrative activity and/or a newly dropped executable on the same host, suggesting the persistence mechanism was set up as part of an ongoing intrusion rather than routine IT work."

    if sig.is_privileged_account(window.user):
        factors.append(("created under a privileged account", 10))

    start, end = _span(evidence)
    return [RuleMatch(sorted({e.event_id for e in evidence}), factors, explanation, start, end)]


RULE_PERSISTENCE = Rule(
    rule_id="RULE-PERSIST-001",
    name="Persistence via Scheduled Task / Service",
    description="Detects creation of a scheduled task, service, or startup modification, escalating when preceded by administrative or file-drop activity.",
    base_points=25,
    mitre_technique="T1053.005",
    recommended_investigation=[
        "Review the scheduled task/service definition and its target executable.",
        "Determine who created it and whether it was change-managed.",
        "Check the target executable's origin and whether it was recently dropped to disk.",
    ],
    evaluate=_eval_persistence,
)


# ---------------------------------------------------------------------------
# Scenario D -- Lateral movement
# ---------------------------------------------------------------------------

def _eval_lateral_movement(window: EntityWindow) -> list[RuleMatch]:
    remote_auth = [e for e in window.events if sig.event_type_matches(e, "remote_login", "remote_auth", "authentication_remote")]
    remote_exec = [e for e in window.events if sig.event_type_matches(e, "remote_process", "remote_service", "service_creation", "remote_execution")]
    if not remote_auth or not remote_exec:
        return []

    factors = [("authentication to a second host followed by remote process/service activity", 30)]
    evidence = remote_auth + remote_exec
    explanation = "The same account authenticated to another host and remote process or service activity followed, consistent with lateral movement using valid credentials."

    if sig.is_privileged_account(window.user):
        factors.append(("privileged account used for lateral movement", 15))

    start, end = _span(evidence)
    return [RuleMatch(sorted({e.event_id for e in evidence}), factors, explanation, start, end)]


RULE_LATERAL_MOVEMENT = Rule(
    rule_id="RULE-LATERAL-001",
    name="Lateral Movement via Remote Services",
    description="Detects authentication to a second host followed by remote process or service execution, indicating movement between systems using a shared credential.",
    base_points=30,
    mitre_technique="T1021",
    recommended_investigation=[
        "Map every host the account authenticated to in the incident window.",
        "Determine whether this account normally accesses these hosts.",
        "Check for the same process/service pattern on other hosts.",
    ],
    evaluate=_eval_lateral_movement,
)


# ---------------------------------------------------------------------------
# Scenario E -- Data collection / simulated exfiltration
# ---------------------------------------------------------------------------

def _eval_exfiltration(window: EntityWindow) -> list[RuleMatch]:
    collection = [e for e in window.events if sig.event_type_matches(e, "file_collection", "file_creation") ]
    archives = [e for e in window.events if sig.event_type_matches(e, "archive_creation") or sig.is_archive_file(e.file)]
    outbound = [e for e in window.events if sig.event_type_matches(e, "outbound_transfer", "outbound_connection")]

    if not archives or not outbound:
        return []

    factors = [("archive created shortly before an outbound transfer", 30)]
    evidence = archives + outbound
    explanation = "Files were archived and an outbound transfer followed, matching a data-collection-then-exfiltration pattern."

    if collection:
        factors.append(("preceded by file collection activity", 15))
        evidence += collection
        explanation = "Files were collected, archived, and then transferred outbound in sequence, matching a staged exfiltration pattern."

    if any(sig.is_external_ip(e.destination_ip) for e in outbound):
        factors.append(("transfer destination is an external IP address", 20))

    start, end = _span(evidence)
    return [RuleMatch(sorted({e.event_id for e in evidence}), factors, explanation, start, end)]


RULE_EXFILTRATION = Rule(
    rule_id="RULE-EXFIL-001",
    name="Data Collection and Simulated Exfiltration",
    description="Detects a file-collection, archive-creation, and outbound-transfer sequence consistent with staged data exfiltration. All bundled evidence is synthetic/simulated.",
    base_points=30,
    mitre_technique="T1560",
    recommended_investigation=[
        "Identify exactly which files were archived.",
        "Determine the destination of the outbound transfer and whether it is sanctioned.",
        "Check whether the account/host normally performs bulk archive operations.",
    ],
    evaluate=_eval_exfiltration,
)


# ---------------------------------------------------------------------------
# Privilege / account manipulation
# ---------------------------------------------------------------------------

def _eval_account_manipulation(window: EntityWindow) -> list[RuleMatch]:
    changes = [e for e in window.events if sig.event_type_matches(e, "group_membership", "new_account", "privilege_escalation")]
    if not changes:
        return []
    factors = [("account privilege or group membership modified", 20)]
    evidence = list(changes)
    explanation = "An account's group membership or privilege level was modified, or a new account was created."

    recent_admin_login = [
        e for e in window.events
        if e.timestamp <= changes[0].timestamp
        and sig.event_type_matches(e, "admin", "successful_login")
    ]
    if recent_admin_login:
        factors.append(("performed shortly after an administrative login", 15))
        evidence += recent_admin_login

    start, end = _span(evidence)
    return [RuleMatch(sorted({e.event_id for e in evidence}), factors, explanation, start, end)]


RULE_ACCOUNT_MANIPULATION = Rule(
    rule_id="RULE-PRIV-001",
    name="Account or Privilege Manipulation",
    description="Detects new account creation or group membership/privilege changes, especially shortly after an administrative login.",
    base_points=20,
    mitre_technique="T1098",
    recommended_investigation=[
        "Verify the change request/change ticket for this account modification.",
        "Confirm the modification was performed by an authorized administrator.",
    ],
    evaluate=_eval_account_manipulation,
)


ALL_RULES: list[Rule] = [
    RULE_BRUTE_FORCE,
    RULE_UNUSUAL_LOGIN,
    RULE_POWERSHELL,
    RULE_PERSISTENCE,
    RULE_LATERAL_MOVEMENT,
    RULE_EXFILTRATION,
    RULE_ACCOUNT_MANIPULATION,
]
