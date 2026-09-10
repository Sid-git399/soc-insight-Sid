"""
Small, named heuristics used by multiple detection rules.

Keeping these as standalone functions (rather than inline regex scattered
through rules_data.py) is what lets the UI show *why* a rule fired: each
one maps directly to a labeled scoring factor.
"""
from __future__ import annotations

import ipaddress
import re

from soc_insight.models import NormalizedEvent

SUSPICIOUS_PROCESSES = {
    "powershell.exe", "powershell", "pwsh", "pwsh.exe",
    "cmd.exe", "cmd", "mshta.exe", "wscript.exe", "cscript.exe",
    "rundll32.exe", "certutil.exe", "regsvr32.exe",
}

PRIVILEGED_ACCOUNT_HINTS = {"administrator", "admin", "root", "domain admin", "svc_admin"}

ENCODED_COMMAND_FLAG_RE = re.compile(r"-(?:e|enc|encodedcommand)\b", re.IGNORECASE)
BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

ARCHIVE_EXTENSIONS = (".zip", ".rar", ".7z", ".tar", ".gz", ".tgz")


def is_suspicious_process(process: str | None) -> bool:
    if not process:
        return False
    return process.strip().lower() in SUSPICIOUS_PROCESSES


def is_powershell(process: str | None) -> bool:
    if not process:
        return False
    return process.strip().lower() in {"powershell.exe", "powershell", "pwsh", "pwsh.exe"}


def has_encoded_command(command: str | None) -> bool:
    if not command:
        return False
    if ENCODED_COMMAND_FLAG_RE.search(command):
        return True
    return bool(BASE64_BLOB_RE.search(command))


def is_privileged_account(user: str | None) -> bool:
    if not user:
        return False
    return user.strip().lower() in PRIVILEGED_ACCOUNT_HINTS


def is_external_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)


def is_archive_file(filename: str | None) -> bool:
    if not filename:
        return False
    lower = filename.lower()
    return lower.endswith(ARCHIVE_EXTENSIONS)


def event_type_matches(event: NormalizedEvent, *fragments: str) -> bool:
    et = (event.event_type or "").lower()
    return any(frag in et for frag in fragments)
