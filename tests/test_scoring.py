from soc_insight.scoring import score_match


def test_score_matches_documented_example():
    # Base 40 + suspicious process 15 + encoded command 15 + privileged 10 + external 10 = 90
    score, severity, breakdown = score_match(
        40,
        [
            ("suspicious process", 15),
            ("encoded command", 15),
            ("privileged account", 10),
            ("external connection", 10),
        ],
    )
    assert score == 90
    assert severity == "CRITICAL"
    assert breakdown[0]["factor"] == "base severity for this detection pattern"
    assert len(breakdown) == 5


def test_score_clamped_to_100():
    score, severity, _ = score_match(80, [("a", 50), ("b", 50)])
    assert score == 100
    assert severity == "CRITICAL"


def test_score_clamped_to_0():
    score, severity, _ = score_match(-10, [])
    assert score == 0
    assert severity == "INFO"


def test_severity_bands():
    from soc_insight.models import severity_from_score
    assert severity_from_score(0) == "INFO"
    assert severity_from_score(24) == "INFO"
    assert severity_from_score(25) == "LOW"
    assert severity_from_score(49) == "LOW"
    assert severity_from_score(50) == "MEDIUM"
    assert severity_from_score(74) == "MEDIUM"
    assert severity_from_score(75) == "HIGH"
    assert severity_from_score(89) == "HIGH"
    assert severity_from_score(90) == "CRITICAL"
    assert severity_from_score(100) == "CRITICAL"
