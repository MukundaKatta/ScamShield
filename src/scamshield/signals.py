"""Signal extraction for scam / phishing detection.

``core.py`` hosts the scoring and CLI glue. This module is the catalogue
of individual *signals* that feed the score — each one a small, unit-
testable function returning an evidence object. Keeping them separate
means we can add a new heuristic without touching the scorer, and the
report page can cite the exact signal name that fired.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List
import re
from urllib.parse import urlparse


@dataclass(frozen=True)
class Signal:
    """A single piece of evidence extracted from a message."""

    name: str
    weight: float  # 0..1; how much this signal contributes to the scam score
    detail: str
    matches: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "weight": self.weight,
            "detail": self.detail,
            "matches": list(self.matches),
        }


URGENCY_WORDS = (
    "urgent", "immediately", "right now", "act now", "final notice",
    "last chance", "within 24 hours", "expires today", "suspended",
)

AUTHORITY_IMPERSONATION = (
    "irs", "hmrc", "ato", "cra", "fbi", "police", "court",
    "microsoft support", "apple support", "amazon security",
    "bank of america", "chase", "paypal security", "customs",
)

MONEY_LURES = (
    "wire transfer", "gift card", "bitcoin", "crypto", "western union",
    "moneygram", "itunes card", "google play card", "steam card",
    "refund", "unclaimed", "inheritance", "lottery", "prize",
)

CRED_REQUESTS = (
    "verify your account", "confirm your password", "ssn", "social security",
    "date of birth", "one-time code", "otp", "2fa code", "security code",
)

# Common lookalike-domain patterns: digits-for-letters and hyphenated brands.
SUSPICIOUS_DOMAIN_RE = re.compile(
    r"\b(?:paypa1|g00gle|amaz0n|micros0ft|app1e|faceb00k|netfiix|bank-of-[a-z]+)\.\w+",
    re.IGNORECASE,
)

URL_RE = re.compile(r"https?://[^\s)>\"']+", re.IGNORECASE)


def _contains_any(text: str, needles: tuple[str, ...]) -> tuple[str, ...]:
    lower = text.lower()
    return tuple(n for n in needles if n in lower)


def urgency(text: str) -> Signal | None:
    hits = _contains_any(text, URGENCY_WORDS)
    if not hits:
        return None
    return Signal(
        name="urgency",
        weight=min(0.35, 0.12 * len(hits)),
        detail="Pressures the reader to act before thinking.",
        matches=hits,
    )


def authority_impersonation(text: str) -> Signal | None:
    hits = _contains_any(text, AUTHORITY_IMPERSONATION)
    if not hits:
        return None
    return Signal(
        name="authority_impersonation",
        weight=0.35,
        detail="Claims to be a government agency or major brand.",
        matches=hits,
    )


def money_lure(text: str) -> Signal | None:
    hits = _contains_any(text, MONEY_LURES)
    if not hits:
        return None
    return Signal(
        name="money_lure",
        weight=0.3,
        detail="Asks for payment via untraceable methods or promises a prize.",
        matches=hits,
    )


def credential_request(text: str) -> Signal | None:
    hits = _contains_any(text, CRED_REQUESTS)
    if not hits:
        return None
    return Signal(
        name="credential_request",
        weight=0.4,
        detail="Requests passwords, SSNs, or one-time codes.",
        matches=hits,
    )


def suspicious_link(text: str) -> Signal | None:
    lookalike = SUSPICIOUS_DOMAIN_RE.findall(text)
    if lookalike:
        return Signal(
            name="suspicious_link",
            weight=0.45,
            detail="Contains a lookalike domain spoofing a known brand.",
            matches=tuple(lookalike),
        )
    # Short redirect-ish hosts.
    short_hosts = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"}
    hits: list[str] = []
    for url in URL_RE.findall(text):
        host = urlparse(url).netloc.lower()
        if host in short_hosts:
            hits.append(url)
    if hits:
        return Signal(
            name="shortened_url",
            weight=0.2,
            detail="Uses a URL shortener that hides the real destination.",
            matches=tuple(hits),
        )
    return None


def all_caps_shouting(text: str) -> Signal | None:
    letters = [c for c in text if c.isalpha()]
    if len(letters) < 20:
        return None
    upper_ratio = sum(1 for c in letters if c.isupper()) / len(letters)
    if upper_ratio < 0.6:
        return None
    return Signal(
        name="all_caps",
        weight=0.1,
        detail="Message is shouting in all caps.",
    )


SIGNALS: tuple[Callable[[str], Signal | None], ...] = (
    urgency,
    authority_impersonation,
    money_lure,
    credential_request,
    suspicious_link,
    all_caps_shouting,
)


def extract(text: str) -> List[Signal]:
    """Run every signal detector and return the ones that fired."""
    return [s for s in (fn(text) for fn in SIGNALS) if s is not None]


def score(signals: List[Signal]) -> float:
    """Combine signals with diminishing returns: 1 - prod(1 - w_i)."""
    acc = 1.0
    for s in signals:
        acc *= 1.0 - max(0.0, min(1.0, s.weight))
    return round(1.0 - acc, 3)
