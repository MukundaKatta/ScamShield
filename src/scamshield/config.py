"""Detection thresholds, pattern database, and configuration."""

from __future__ import annotations

from typing import Dict, List

from pydantic import BaseModel, Field


class DetectionConfig(BaseModel):
    """Configuration for the ScamDetector engine."""

    # --- Sensitivity (0.0 = lenient, 1.0 = strict) -----------------------
    sensitivity: float = Field(default=0.5, ge=0.0, le=1.0)

    # --- Score thresholds -------------------------------------------------
    low_risk_threshold: int = Field(default=25)
    medium_risk_threshold: int = Field(default=50)
    high_risk_threshold: int = Field(default=75)

    # --- Urgency language -------------------------------------------------
    urgency_phrases: List[str] = Field(default_factory=lambda: [
        "act now",
        "limited time",
        "expires today",
        "immediate action required",
        "urgent",
        "don't delay",
        "last chance",
        "only hours left",
        "respond immediately",
        "time sensitive",
        "hurry",
        "deadline",
        "final notice",
        "suspension notice",
    ])

    # --- Financial keywords -----------------------------------------------
    financial_keywords: List[str] = Field(default_factory=lambda: [
        "wire transfer",
        "bitcoin",
        "gift card",
        "cryptocurrency",
        "western union",
        "moneygram",
        "bank account",
        "routing number",
        "ssn",
        "social security number",
        "credit card number",
        "payment",
        "cash app",
        "zelle",
        "venmo",
        "paypal",
        "money order",
    ])

    # --- Impersonation patterns -------------------------------------------
    impersonation_patterns: List[str] = Field(default_factory=lambda: [
        "irs",
        "social security administration",
        "social security",
        "fbi",
        "microsoft support",
        "apple support",
        "amazon support",
        "your bank",
        "federal government",
        "tax authority",
        "customs office",
        "interpol",
        "police department",
        "court order",
    ])

    # --- Phishing patterns ------------------------------------------------
    phishing_patterns: List[str] = Field(default_factory=lambda: [
        "verify your account",
        "click here",
        "confirm your identity",
        "update your payment",
        "reset your password",
        "unusual activity",
        "account suspended",
        "login attempt",
        "security alert",
        "verify your information",
        "confirm your details",
        "unlock your account",
    ])

    # --- Suspicious URL indicators ----------------------------------------
    suspicious_url_indicators: List[str] = Field(default_factory=lambda: [
        "bit.ly",
        "tinyurl",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "rebrand.ly",
        "shorturl",
        ".xyz",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".top",
        ".buzz",
    ])

    # --- Category weights (must sum roughly to 100) -----------------------
    category_weights: Dict[str, float] = Field(default_factory=lambda: {
        "urgency": 20.0,
        "financial": 25.0,
        "impersonation": 20.0,
        "phishing": 20.0,
        "suspicious_url": 15.0,
    })

    # --- Custom patterns (user-supplied) ----------------------------------
    custom_patterns: Dict[str, List[str]] = Field(default_factory=dict)
