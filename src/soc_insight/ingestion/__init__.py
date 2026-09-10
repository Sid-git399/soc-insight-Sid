from __future__ import annotations

from pathlib import Path

from soc_insight.models import NormalizedEvent, IngestionIssue
from .parsers import PARSERS_BY_FORMAT, detect_format, FileTooLargeError
from .normalizer import normalize_records


def load_file(path: str | Path) -> tuple[list[NormalizedEvent], list[IngestionIssue]]:
    """
    Loads a single log file (json/ndjson/csv/text log) from disk, parses it
    with the appropriate safe parser, and normalizes the resulting records.
    Never raises for malformed *content* -- only for files exceeding the
    hard size cap, which callers should surface to the user explicitly.
    """
    path = Path(path)
    fmt = detect_format(path.name)
    raw_bytes = path.read_bytes()
    parser = PARSERS_BY_FORMAT[fmt]
    records, parse_issues = parser(raw_bytes, path.name)
    events, normalize_issues = normalize_records(records, path.name, fmt)
    return events, parse_issues + normalize_issues


def load_bytes(raw_bytes: bytes, filename: str) -> tuple[list[NormalizedEvent], list[IngestionIssue]]:
    fmt = detect_format(filename)
    parser = PARSERS_BY_FORMAT[fmt]
    records, parse_issues = parser(raw_bytes, filename)
    events, normalize_issues = normalize_records(records, filename, fmt)
    return events, parse_issues + normalize_issues


__all__ = ["load_file", "load_bytes", "FileTooLargeError"]
