import pytest

from soc_insight.ingestion.parsers import parse_json, parse_csv, FileTooLargeError, MAX_FILE_BYTES


def test_json_size_limit_enforced():
    huge = b"a" * (MAX_FILE_BYTES + 1)
    with pytest.raises(FileTooLargeError):
        parse_json(huge, "huge.json")


def test_csv_size_limit_enforced():
    huge = b"a" * (MAX_FILE_BYTES + 1)
    with pytest.raises(FileTooLargeError):
        parse_csv(huge, "huge.csv")


def test_command_field_containing_shell_syntax_is_never_executed():
    """
    Uploaded logs are data. A command field containing shell metacharacters
    must be stored/displayed as a string only, never passed to a shell.
    This test asserts the parsing/normalization layer performs no
    subprocess/eval/exec calls -- it just proves the value round-trips as
    inert text.
    """
    from soc_insight.ingestion import load_bytes

    raw = b'[{"timestamp": "2026-01-01T00:00:00Z", "event_type": "process_creation", "host": "H", "command": "; rm -rf / #"}]'
    events, issues = load_bytes(raw, "t.json")
    assert issues == []
    assert events[0].command == "; rm -rf / #"  # stored verbatim as data, not executed


def test_record_count_cap_applied_to_json():
    from soc_insight.ingestion.parsers import MAX_RECORDS_PER_FILE
    records_json = b"[" + b",".join([b'{"a":1}'] * (MAX_RECORDS_PER_FILE + 10)) + b"]"
    records, issues = parse_json(records_json, "many.json")
    assert len(records) == MAX_RECORDS_PER_FILE
    assert any("cap" in i.reason for i in issues)


def test_non_dict_top_level_json_rejected_gracefully():
    records, issues = parse_json(b'"just a string"', "bad.json")
    assert records == []
    assert len(issues) == 1


def test_csv_extra_columns_do_not_crash():
    raw = b"timestamp,event_type\n2026-01-01T00:00:00Z,x,extra_column_value\n"
    records, issues = parse_csv(raw, "t.csv")
    assert len(records) == 1
    assert any("extra columns" in i.reason for i in issues)


def test_hunting_query_has_no_eval_injection_path():
    """The hunting query language must not support arbitrary Python eval."""
    from soc_insight.hunting import search_events, QuerySyntaxError
    from soc_insight.ingestion import load_bytes

    events, _ = load_bytes(
        b'[{"timestamp": "2026-01-01T00:00:00Z", "event_type": "x", "host": "H"}]', "t.json"
    )
    with pytest.raises(QuerySyntaxError):
        search_events(events, "__import__('os').system('echo pwned')")
