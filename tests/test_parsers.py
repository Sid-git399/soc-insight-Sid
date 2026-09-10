from soc_insight.ingestion import load_bytes
from soc_insight.ingestion.parsers import parse_json, parse_csv, parse_ndjson, parse_text_log


def test_parse_valid_json_array():
    raw = b'[{"timestamp": "2026-01-01T00:00:00Z", "event_type": "x", "host": "H"}]'
    records, issues = parse_json(raw, "test.json")
    assert len(records) == 1
    assert issues == []


def test_parse_malformed_json_reports_issue_not_crash():
    raw = b'{not valid json'
    records, issues = parse_json(raw, "bad.json")
    assert records == []
    assert len(issues) == 1
    assert "invalid JSON" in issues[0].reason


def test_parse_ndjson_skips_bad_lines():
    raw = b'{"a": 1}\nnot json\n{"b": 2}\n'
    records, issues = parse_ndjson(raw, "test.ndjson")
    assert len(records) == 2
    assert len(issues) == 1


def test_parse_csv_basic():
    raw = b"timestamp,event_type,host\n2026-01-01T00:00:00Z,auth_failed_login,WKS-1\n"
    records, issues = parse_csv(raw, "test.csv")
    assert len(records) == 1
    assert records[0]["host"] == "WKS-1"
    assert issues == []


def test_parse_csv_no_header_reports_issue():
    raw = b""
    records, issues = parse_csv(raw, "empty.csv")
    assert records == []
    assert len(issues) == 1


def test_parse_text_log_key_value():
    raw = b"2026-01-01T00:00:00Z event_type=auth_failed_login host=WKS-1 user=jdupont\n"
    records, issues = parse_text_log(raw, "test.log")
    assert len(records) == 1
    assert records[0]["event_type"] == "auth_failed_login"
    assert issues == []


def test_parse_text_log_unrecognized_line_reported():
    raw = b"this line has no timestamp at all\n"
    records, issues = parse_text_log(raw, "test.log")
    assert records == []
    assert len(issues) == 1


def test_load_bytes_normalizes_full_record():
    raw = b'[{"timestamp": "2026-01-01T00:00:00Z", "event_type": "auth_failed_login", "host": "WKS-1", "user": "jdupont", "src_ip": "10.0.0.5"}]'
    events, issues = load_bytes(raw, "test.json")
    assert len(events) == 1
    assert issues == []
    e = events[0]
    assert e.host == "WKS-1"
    assert e.user == "jdupont"
    assert e.source_ip == "10.0.0.5"  # alias mapping from src_ip


def test_normalize_missing_timestamp_is_reported_not_crashed():
    raw = b'[{"event_type": "auth_failed_login", "host": "WKS-1"}]'
    events, issues = load_bytes(raw, "test.json")
    assert events == []
    assert len(issues) == 1
    assert "timestamp" in issues[0].reason


def test_normalize_missing_event_type_is_reported():
    raw = b'[{"timestamp": "2026-01-01T00:00:00Z", "host": "WKS-1"}]'
    events, issues = load_bytes(raw, "test.json")
    assert events == []
    assert len(issues) == 1
    assert "event_type" in issues[0].reason


def test_oversized_file_raises_explicit_error(tmp_path):
    from soc_insight.ingestion.parsers import FileTooLargeError, parse_json
    huge = b"[" + b"1" * (11 * 1024 * 1024) + b"]"
    try:
        parse_json(huge, "huge.json")
        assert False, "expected FileTooLargeError"
    except FileTooLargeError:
        pass
