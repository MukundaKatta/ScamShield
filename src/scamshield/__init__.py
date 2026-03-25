"""ScamShield — Fraud and scam detection engine for text messages and emails."""

__version__ = "0.1.0"

from scamshield.core import (
    BulkScanner,
    RiskScore,
    ScamDetector,
    ScamReport,
)
from scamshield.config import DetectionConfig
from scamshield.utils import normalize_text, extract_urls, keyword_match_score

__all__ = [
    "BulkScanner",
    "DetectionConfig",
    "RiskScore",
    "ScamDetector",
    "ScamReport",
    "normalize_text",
    "extract_urls",
    "keyword_match_score",
]
