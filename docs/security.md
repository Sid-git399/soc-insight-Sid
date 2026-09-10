# Security Considerations

SOC-Insight ingests attacker-shaped data by design (that's the point of a
detection lab), so its own handling of that data has to be defensive.

## Uploaded logs are data, never code

This is the single most important rule in the codebase. Nowhere does
SOC-Insight call `eval`, `exec`, `subprocess`, `os.system`, or a shell
against anything derived from an ingested log file. A `command` field
containing shell metacharacters (e.g. `; rm -rf / #`) is stored and
displayed as an inert string — see
`tests/test_security.py::test_command_field_containing_shell_syntax_is_never_executed`.

The threat-hunting query language (`hunting/search.py`) is a small,
hand-rolled grammar (`field OP "value"`, `AND`/`OR`) with no `eval` path;
`tests/test_security.py::test_hunting_query_has_no_eval_injection_path`
asserts that a classic `__import__('os').system(...)` payload is rejected
as a syntax error, not executed.

## Input validation and limits

- **File size cap:** 10 MB per ingested file
  (`ingestion/parsers.MAX_FILE_BYTES`), enforced before parsing.
- **Record count cap:** 50,000 records per file
  (`ingestion/parsers.MAX_RECORDS_PER_FILE`); excess records are dropped
  with a reported issue rather than exhausting memory.
- **Upload endpoint (`POST /api/ingest`):** validates the file extension
  against an allow-list (`.json`, `.ndjson`, `.jsonl`, `.csv`, `.log`,
  `.txt`) and enforces the same 10 MB cap at the HTTP layer before the
  parser ever sees the bytes.
- **Note length cap:** analyst notes are capped at 4,000 characters at
  the API layer.

## Safe parsing

- JSON/NDJSON: parsed with the standard library's `json` module only
  (no `eval`-based parsing, no YAML with unsafe loaders).
- CSV: parsed with the standard library's `csv.DictReader`; rows with
  more columns than the header are tolerated and reported, not crashed
  on.
- Malformed records at any stage (invalid JSON, missing timestamp,
  missing event type, non-numeric port, etc.) become an `IngestionIssue`
  and are skipped — a single bad line never aborts ingestion of the rest
  of the file. See `tests/test_parsers.py`.

## No path traversal

The Flask app never opens a file path built from user input outside of
the (extension-checked, size-checked) uploaded byte stream. The static
frontend route (`app.py::static_files`) only serves files that literally
exist inside `frontend/` via `Flask.send_from_directory`, which itself
resolves and checks the path against its configured root; any other path
falls back to serving the SPA shell (`index.html`) rather than reading
arbitrary filesystem paths.

## No secrets in the repository

No API key, password, or token is hard-coded anywhere in this codebase.
The one optional external integration point — a local model endpoint for
richer AI-assisted narrative generation — is configured entirely through
the `SOC_INSIGHT_LOCAL_MODEL_URL` environment variable
(`analysis/local_model_provider.py`) and is never required for the
application to run. If that endpoint is unreachable or misconfigured,
`LocalModelProvider` fails closed to the local, rule-based provider
rather than raising an error to the user.

## Honest IOC and AI language

- IOC risk labels are limited to `OBSERVED`, `SUSPICIOUS`, and
  `ASSOCIATED_WITH_INCIDENT` — SOC-Insight never claims an indicator is
  confirmed malicious purely on its own authority, since it performs no
  external threat-intelligence reputation lookup.
  (`tests/test_ioc.py::test_no_false_malicious_claim_language`)
- AI-assisted analysis text scales its confidence language to the
  detection score and analyst classification (`analysis/rule_based_provider.py::_confidence_phrase`)
  rather than asserting certainty uniformly.

## Dependency footprint

The runtime dependency list is intentionally minimal: Flask for the web
server, and the Python standard library for everything else (parsing,
regex-based IOC extraction, dataclasses). Fewer dependencies means a
smaller surface for supply-chain risk in a project of this scope. Run
`pip list --outdated` or `pip-audit` periodically if you extend this
project for real use.

## What this project does not attempt to defend against

Being transparent about scope (see also the README's Limitations
section): this is a single-process, single-user, in-memory local lab. It
has no authentication, no network-facing production hardening (it runs
Flask's development server), and no protection against a malicious actor
who already has local access to the machine running it. Do not expose
`app.py` to an untrusted network without putting a real authentication
layer and a production WSGI server in front of it.
