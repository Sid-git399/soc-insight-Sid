"""
Threat hunting query engine.

Supports a small, safe query language over normalized events -- no `eval`,
no arbitrary code execution. Grammar:

    query      := clause (BOOL clause)*
    clause     := FIELD OP VALUE
    OP         := "=" | "!=" | "contains"
    BOOL       := "AND" | "OR"   (case-insensitive; left-to-right, no precedence)
    VALUE      := "quoted string" | bareword

Examples:
    source_ip = "10.0.0.5"
    user = "administrator" OR user = "svc_backup"
    process contains "powershell"
    severity = "HIGH" AND event_type contains "network"
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from soc_insight.models import NormalizedEvent

FIELD_MAP = {
    "source_ip": lambda e: e.source_ip,
    "destination_ip": lambda e: e.destination_ip,
    "user": lambda e: e.user,
    "host": lambda e: e.host,
    "process": lambda e: e.process,
    "command": lambda e: e.command,
    "file": lambda e: e.file,
    "domain": lambda e: e.domain,
    "event_type": lambda e: e.event_type,
    "severity": lambda e: e.severity_hint,
}

_TOKEN_RE = re.compile(
    r'''\s*(?:(?P<bool>AND|OR)|(?P<field>\w+)\s*(?P<op>=|!=|contains)\s*(?P<value>"(?:[^"\\]|\\.)*"|\S+))''',
    re.IGNORECASE,
)


class QuerySyntaxError(Exception):
    pass


@dataclass
class Clause:
    field: str
    op: str
    value: str
    bool_prefix: str | None  # "AND"/"OR" joining to the previous clause, or None for the first


def parse_query(query: str) -> list[Clause]:
    clauses: list[Clause] = []
    pos = 0
    pending_bool = None
    query = query.strip()
    if not query:
        return clauses

    while pos < len(query):
        m = _TOKEN_RE.match(query, pos)
        if not m:
            raise QuerySyntaxError(f"could not parse query near: '{query[pos:pos+30]}'")
        if m.group("bool"):
            pending_bool = m.group("bool").upper()
        else:
            field = m.group("field").lower()
            if field not in FIELD_MAP:
                raise QuerySyntaxError(
                    f"unknown field '{field}'. Supported fields: {', '.join(sorted(FIELD_MAP))}"
                )
            value = m.group("value")
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1].replace('\\"', '"')
            clauses.append(Clause(field=field, op=m.group("op").lower(), value=value, bool_prefix=pending_bool))
            pending_bool = None
        pos = m.end()
    return clauses


def _clause_matches(clause: Clause, event: NormalizedEvent) -> bool:
    getter = FIELD_MAP[clause.field]
    field_value = getter(event)
    if field_value is None:
        return False
    field_value = str(field_value)
    if clause.op == "=":
        return field_value.lower() == clause.value.lower()
    if clause.op == "!=":
        return field_value.lower() != clause.value.lower()
    if clause.op == "contains":
        return clause.value.lower() in field_value.lower()
    return False


def event_matches(clauses: list, event: NormalizedEvent) -> bool:
    if not clauses:
        return True
    result = _clause_matches(clauses[0], event)
    for clause in clauses[1:]:
        outcome = _clause_matches(clause, event)
        if clause.bool_prefix == "OR":
            result = result or outcome
        else:  # default AND
            result = result and outcome
    return result


def search_events(events: list, query: str) -> list:
    clauses = parse_query(query)
    return [e for e in events if event_matches(clauses, e)]
