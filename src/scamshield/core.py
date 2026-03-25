"""Core detection engine — ScamDetector, RiskScore, ScamReport, BulkScanner."""

from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from scamshield.config import DetectionConfig
from scamshield.utils import (
    check_suspicious_urls,
    classify_scam_type,
    keyword_match_score,
    normalize_text,
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class RiskScore(BaseModel):
    """Numeric risk assessment with per-category breakdown."""

    total: int = Field(ge=0, le=100, description="Overall risk score 0-100")
    breakdown: Dict[str, float] = Field(
        default_factory=dict,
        description="Score contribution per category",
    )
    level: str = Field(default="low", description="low | medium | high | critical")

    @classmethod
    def from_breakdown(cls, breakdown: Dict[str, float], config: DetectionConfig) -> "RiskScore":
        """Build a RiskScore from a category breakdown dict."""
        total = int(min(100, round(sum(breakdown.values()))))
        if total >= config.high_risk_threshold:
            level = "critical"
        elif total >= config.medium_risk_threshold:
            level = "high"
        elif total >= config.low_risk_threshold:
            level = "medium"
        else:
            level = "low"
        return cls(total=total, breakdown=breakdown, level=level)


class ScamReport(BaseModel):
    """Detailed analysis report for a single message."""

    message: str
    risk_score: RiskScore
    flagged_phrases: List[str] = Field(default_factory=list)
    risk_category: str = Field(default="unknown")
    confidence: float = Field(ge=0.0, le=1.0)
    scam_type: str = Field(default="unknown")
    explanation: str = Field(default="")


# ---------------------------------------------------------------------------
# ScamDetector
# ---------------------------------------------------------------------------


class ScamDetector:
    """Analyse text messages for fraud / scam indicators.

    Parameters
    ----------
    config : DetectionConfig, optional
        Override default thresholds, patterns, or sensitivity.
    """

    def __init__(self, config: Optional[DetectionConfig] = None) -> None:
        self.config = config or DetectionConfig()

    # -- public API --------------------------------------------------------

    def analyze(self, text: str) -> ScamReport:
        """Return a full :class:`ScamReport` for *text*."""
        breakdown: Dict[str, float] = {}
        all_flagged: List[str] = []

        # 1. Urgency
        score, matched = keyword_match_score(
            text, self.config.urgency_phrases, sensitivity=self.config.sensitivity
        )
        weighted = round(score * self.config.category_weights["urgency"], 2)
        breakdown["urgency"] = weighted
        all_flagged.extend(matched)

        # 2. Financial
        score, matched = keyword_match_score(
            text, self.config.financial_keywords, sensitivity=self.config.sensitivity
        )
        weighted = round(score * self.config.category_weights["financial"], 2)
        breakdown["financial"] = weighted
        all_flagged.extend(matched)

        # 3. Impersonation
        score, matched = keyword_match_score(
            text, self.config.impersonation_patterns, sensitivity=self.config.sensitivity
        )
        weighted = round(score * self.config.category_weights["impersonation"], 2)
        breakdown["impersonation"] = weighted
        all_flagged.extend(matched)

        # 4. Phishing
        score, matched = keyword_match_score(
            text, self.config.phishing_patterns, sensitivity=self.config.sensitivity
        )
        weighted = round(score * self.config.category_weights["phishing"], 2)
        breakdown["phishing"] = weighted
        all_flagged.extend(matched)

        # 5. Suspicious URLs
        score, matched = check_suspicious_urls(text, self.config.suspicious_url_indicators)
        weighted = round(score * self.config.category_weights["suspicious_url"], 2)
        breakdown["suspicious_url"] = weighted
        all_flagged.extend(matched)

        # 6. Custom patterns
        for cat_name, patterns in self.config.custom_patterns.items():
            score, matched = keyword_match_score(
                text, patterns, sensitivity=self.config.sensitivity
            )
            custom_weight = self.config.category_weights.get(cat_name, 10.0)
            weighted = round(score * custom_weight, 2)
            breakdown[cat_name] = weighted
            all_flagged.extend(matched)

        risk_score = RiskScore.from_breakdown(breakdown, self.config)
        scam_type = classify_scam_type(breakdown)
        confidence = round(risk_score.total / 100, 2)

        explanation = self._build_explanation(risk_score, all_flagged, scam_type)

        return ScamReport(
            message=text,
            risk_score=risk_score,
            flagged_phrases=sorted(set(all_flagged)),
            risk_category=risk_score.level,
            confidence=confidence,
            scam_type=scam_type,
            explanation=explanation,
        )

    def quick_score(self, text: str) -> int:
        """Return only the total risk score (0-100) for *text*."""
        return self.analyze(text).risk_score.total

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _build_explanation(
        risk_score: RiskScore,
        flagged: List[str],
        scam_type: str,
    ) -> str:
        parts: List[str] = []
        parts.append(f"Risk level: {risk_score.level} ({risk_score.total}/100).")
        if flagged:
            top = flagged[:5]
            parts.append(f"Flagged indicators: {', '.join(top)}.")
        if scam_type != "unknown":
            parts.append(f"Likely scam type: {scam_type}.")
        return " ".join(parts)


# ---------------------------------------------------------------------------
# BulkScanner
# ---------------------------------------------------------------------------


class BulkScanner:
    """Scan multiple messages and return reports sorted by risk.

    Parameters
    ----------
    config : DetectionConfig, optional
        Shared configuration for every scan.
    """

    def __init__(self, config: Optional[DetectionConfig] = None) -> None:
        self.detector = ScamDetector(config=config)

    def scan(self, messages: List[str]) -> List[ScamReport]:
        """Analyze all *messages* and return reports sorted highest-risk first."""
        reports = [self.detector.analyze(m) for m in messages]
        reports.sort(key=lambda r: r.risk_score.total, reverse=True)
        return reports

    def scan_csv(self, path: str, column: str = "message") -> List[ScamReport]:
        """Read a CSV and scan the specified *column*."""
        import csv

        messages: List[str] = []
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                if column in row:
                    messages.append(row[column])
        return self.scan(messages)
