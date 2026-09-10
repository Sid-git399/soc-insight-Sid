"""
Local MITRE ATT&CK knowledge base.

This is intentionally a small, curated subset -- only the techniques that
the bundled detection rules (see detection/rules_data.py) can actually
produce evidence for. SOC-Insight does not claim broader ATT&CK coverage
than what its rules implement.
"""
from __future__ import annotations

MITRE_TECHNIQUES = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries attempt to guess or systematically try credentials "
            "to gain access to accounts when passwords are unknown."
        ),
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "description": (
            "Adversaries obtain and abuse credentials of existing accounts "
            "to gain access, maintain persistence, or elevate privileges."
        ),
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "description": (
            "Adversaries abuse PowerShell for execution, often using "
            "encoded commands to obscure their activity from casual review."
        ),
    },
    "T1027": {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries encode or otherwise obscure command content, such "
            "as Base64-encoded PowerShell, to evade detection and analysis."
        ),
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": (
            "Adversaries communicate using application layer protocols to "
            "blend with normal traffic and avoid detection."
        ),
    },
    "T1053.005": {
        "id": "T1053.005",
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactic": "Persistence / Privilege Escalation / Execution",
        "description": (
            "Adversaries create scheduled tasks to execute programs at "
            "system startup or on a recurring schedule for persistence."
        ),
    },
    "T1569.002": {
        "id": "T1569.002",
        "name": "System Services: Service Execution",
        "tactic": "Execution",
        "description": (
            "Adversaries create or modify services to execute commands, "
            "often for persistence or remote execution during lateral movement."
        ),
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries use valid accounts to log into remote services and "
            "move laterally within a network."
        ),
    },
    "T1074": {
        "id": "T1074",
        "name": "Data Staged",
        "tactic": "Collection",
        "description": (
            "Adversaries stage collected data in a central location, often "
            "compressed or archived, before exfiltration."
        ),
    },
    "T1560": {
        "id": "T1560",
        "name": "Archive Collected Data",
        "tactic": "Collection",
        "description": (
            "Adversaries compress and/or encrypt collected data prior to "
            "exfiltration to reduce size and obscure content."
        ),
    },
    "T1041": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries transfer staged data out of the target environment "
            "using the same channel used for command and control."
        ),
    },
    "T1098": {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "description": (
            "Adversaries modify account properties or group membership to "
            "maintain access or elevate privileges."
        ),
    },
}


def get_technique(technique_id: str) -> dict | None:
    return MITRE_TECHNIQUES.get(technique_id)


def all_techniques() -> list:
    return list(MITRE_TECHNIQUES.values())
