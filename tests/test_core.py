"""Tests for the ScamShield detection engine."""

from __future__ import annotations

import csv
import tempfile
from pathlib import Path

from scamshield.config import DetectionConfig
from scamshield.core import BulkScanner, ScamDetector


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_detector(**kwargs) -> ScamDetector:
    return ScamDetector(config=DetectionConfig(**kwargs))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_phishing_detection():
    """A classic phishing message should score high."""
    detector = _make_detector()
    report = detector.analyze(
        "URGENT: Your account has been suspended. Click here to verify your account "
        "immediately or your access will be revoked. Visit http://bit.ly/secure-login"
    )
    assert report.risk_score.total >= 25
    assert report.risk_score.level in ("medium", "high", "critical")
    assert any("click here" in p for p in report.flagged_phrases)


def test_legitimate_message():
    """A normal, benign message should score low."""
    detector = _make_detector()
    report = detector.analyze(
        "Hey, are we still on for lunch tomorrow at noon? Let me know!"
    )
    assert report.risk_score.total < 25
    assert report.risk_score.level == "low"


def test_urgency_scoring():
    """Messages loaded with urgency language should flag the urgency category."""
    detector = _make_detector()
    report = detector.analyze(
        "Act now! Limited time offer — this deal expires today. "
        "Don't delay, last chance to claim your prize. Hurry!"
    )
    assert report.risk_score.breakdown["urgency"] > 0
    assert "act now" in report.flagged_phrases
    assert "limited time" in report.flagged_phrases


def test_bulk_scan_sorted_by_risk():
    """BulkScanner should return results sorted highest-risk first."""
    scanner = BulkScanner()
    messages = [
        "Hey, want to grab coffee?",
        "URGENT: Wire transfer $5,000 via bitcoin to avoid IRS arrest. Act now!",
        "Your package is on the way, expected delivery Thursday.",
    ]
    reports = scanner.scan(messages)
    scores = [r.risk_score.total for r in reports]
    assert scores == sorted(scores, reverse=True)
    # The scam message should be first
    assert "wire transfer" in reports[0].flagged_phrases


def test_custom_patterns():
    """User-supplied custom patterns should contribute to the score."""
    config = DetectionConfig(
        custom_patterns={"romance": ["i love you", "my darling", "send me money"]},
        category_weights={
            "urgency": 20.0,
            "financial": 25.0,
            "impersonation": 20.0,
            "phishing": 20.0,
            "suspicious_url": 15.0,
            "romance": 15.0,
        },
    )
    detector = ScamDetector(config=config)
    report = detector.analyze("My darling, I love you so much. Please send me money for a plane ticket.")
    assert "romance" in report.risk_score.breakdown
    assert report.risk_score.breakdown["romance"] > 0
    assert "i love you" in report.flagged_phrases


def test_financial_keywords():
    """Financial scam keywords should be detected and scored."""
    detector = _make_detector()
    report = detector.analyze(
        "Please send payment via gift card or bitcoin to the following address."
    )
    assert report.risk_score.breakdown["financial"] > 0
    assert "gift card" in report.flagged_phrases
    assert "bitcoin" in report.flagged_phrases


def test_bulk_scan_csv(tmp_path: Path):
    """BulkScanner.scan_csv should read from a CSV file."""
    csv_file = tmp_path / "messages.csv"
    with open(csv_file, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["id", "message"])
        writer.writeheader()
        writer.writerow({"id": "1", "message": "Act now! Send bitcoin to avoid arrest."})
        writer.writerow({"id": "2", "message": "See you at the meeting tomorrow."})

    scanner = BulkScanner()
    reports = scanner.scan_csv(str(csv_file), column="message")
    assert len(reports) == 2
    assert reports[0].risk_score.total > reports[1].risk_score.total
