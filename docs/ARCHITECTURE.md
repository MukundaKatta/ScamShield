# Architecture

## Overview

ScamShield is a rule-based fraud and scam detection engine designed to analyze text messages and emails for common scam indicators. The engine scores messages on a 0-100 risk scale across multiple detection categories.

## Components

```
src/scamshield/
├── __init__.py      # Public API exports
├── config.py        # DetectionConfig — thresholds, pattern database
├── core.py          # ScamDetector, RiskScore, ScamReport, BulkScanner
├── utils.py         # Text normalization, URL analysis, keyword matching
└── __main__.py      # CLI interface (typer + rich)
```

### Detection Pipeline

1. **Text normalization** — lowercase, whitespace collapse, stripping
2. **Category scoring** — each category (urgency, financial, impersonation, phishing, suspicious URLs) is scored independently
3. **Weight aggregation** — category scores are multiplied by configurable weights and summed
4. **Risk classification** — total score maps to low / medium / high / critical
5. **Report generation** — flagged phrases, scam type, confidence, and explanation

### Detection Categories

| Category | What it detects |
|---|---|
| Urgency | "act now", "limited time", "expires today" |
| Financial | "wire transfer", "bitcoin", "gift card" |
| Impersonation | "IRS", "Social Security", "Microsoft Support" |
| Phishing | "verify your account", "click here", "account suspended" |
| Suspicious URLs | Shortened links (bit.ly), suspicious TLDs (.xyz, .tk) |

### Scam Type Classification

Based on the highest-scoring category, messages are classified as:
- **phishing** — credential harvesting, fake login pages
- **advance-fee** — requests for upfront payment
- **tech-support** — impersonation of tech companies
- **investment** — urgency-driven financial pressure
- **romance** — emotional manipulation (via custom patterns)

### Configuration

All patterns, thresholds, and weights are configurable via `DetectionConfig`. Users can add custom pattern categories to extend detection beyond the built-in rules.

## Design Decisions

- **Pydantic models** for all data structures — validation, serialization, and clear schemas
- **No ML dependencies** — purely rule-based for predictability, speed, and zero cold-start
- **Sensitivity parameter** — single knob to tune false-positive / false-negative tradeoff
- **CSV bulk scanning** — practical for batch analysis of message dumps
