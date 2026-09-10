import pytest

from soc_insight.hunting import search_events, parse_query, QuerySyntaxError
from soc_insight.ingestion import load_bytes

RAW = b"""[
  {"timestamp": "2026-01-01T00:00:00Z", "event_type": "auth_failed_login", "host": "WKS-1", "user": "administrator", "source_ip": "10.0.0.5"},
  {"timestamp": "2026-01-01T00:00:05Z", "event_type": "process_powershell_execution", "host": "WKS-2", "user": "jdupont", "process": "powershell.exe"},
  {"timestamp": "2026-01-01T00:00:10Z", "event_type": "network_outbound_connection", "host": "WKS-2", "user": "jdupont", "destination_ip": "185.220.101.47"}
]"""


def build_events():
    events, _ = load_bytes(RAW, "t.json")
    return events


def test_equals_operator():
    events = build_events()
    results = search_events(events, 'source_ip = "10.0.0.5"')
    assert len(results) == 1
    assert results[0].host == "WKS-1"


def test_contains_operator():
    events = build_events()
    results = search_events(events, 'process contains "powershell"')
    assert len(results) == 1


def test_and_operator():
    events = build_events()
    results = search_events(events, 'host = "WKS-2" AND user = "jdupont"')
    assert len(results) == 2


def test_or_operator():
    events = build_events()
    results = search_events(events, 'user = "administrator" OR user = "jdupont"')
    assert len(results) == 3


def test_not_equals_operator():
    events = build_events()
    results = search_events(events, 'user != "jdupont"')
    assert len(results) == 1


def test_unknown_field_raises_syntax_error():
    events = build_events()
    with pytest.raises(QuerySyntaxError):
        search_events(events, 'nonexistent_field = "x"')


def test_empty_query_matches_nothing_special_returns_all():
    events = build_events()
    clauses = parse_query("")
    assert clauses == []


def test_malformed_query_raises():
    events = build_events()
    with pytest.raises(QuerySyntaxError):
        search_events(events, 'host ~~ "WKS-1"')
