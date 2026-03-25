"""Text normalization, URL analysis, and keyword matching utilities."""

from __future__ import annotations

import re
from typing import List, Tuple


def normalize_text(text: str) -> str:
    """Lowercase, collapse whitespace, and strip the input text."""
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_urls(text: str) -> List[str]:
    """Return all URLs found in *text*."""
    url_pattern = re.compile(
        r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE
    )
    return url_pattern.findall(text)


def keyword_match_score(
    text: str,
    keywords: List[str],
    *,
    sensitivity: float = 0.5,
) -> Tuple[float, List[str]]:
    """Score *text* against a list of *keywords*.

    Returns a tuple of (score 0.0-1.0, list of matched keywords).
    Sensitivity scales the final score: higher sensitivity amplifies
    even a single match.
    """
    normalized = normalize_text(text)
    matched: List[str] = []
    for kw in keywords:
        if kw.lower() in normalized:
            matched.append(kw)

    if not keywords:
        return 0.0, matched

    # Score based on number of matches, not ratio to total patterns.
    # Each match contributes significantly; 3+ matches saturate the category.
    per_match = 0.35 + sensitivity * 0.3  # ~0.5 per match at default sensitivity
    adjusted = min(1.0, len(matched) * per_match)
    return round(adjusted, 4), matched


def check_suspicious_urls(text: str, indicators: List[str]) -> Tuple[float, List[str]]:
    """Detect shortened / suspicious URLs in *text*.

    Returns (score 0.0-1.0, list of suspicious URL fragments found).
    """
    urls = extract_urls(text)
    normalized = normalize_text(text)
    flagged: List[str] = []

    for indicator in indicators:
        ind_lower = indicator.lower()
        # Check inside extracted URLs or raw text (people paste bare domains)
        for url in urls:
            if ind_lower in url.lower():
                flagged.append(indicator)
                break
        else:
            if ind_lower in normalized:
                flagged.append(indicator)

    if not indicators:
        return 0.0, flagged

    raw = len(flagged) / len(indicators)
    score = min(1.0, raw * 3)  # amplify — even one suspicious link is notable
    return round(score, 4), flagged


def classify_scam_type(category_scores: dict) -> str:
    """Return the most likely scam type label based on category scores."""
    mapping = {
        "phishing": "phishing",
        "financial": "advance-fee",
        "impersonation": "tech-support",
        "urgency": "investment",
    }
    if not category_scores:
        return "unknown"

    top_category = max(category_scores, key=category_scores.get)  # type: ignore[arg-type]
    return mapping.get(top_category, "generic")
