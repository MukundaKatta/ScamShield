# ScamShield — Fraud and scam detection engine — analyze messages for phishing, urgency tricks, and financial scam patterns

Fraud and scam detection engine — analyze messages for phishing, urgency tricks, and financial scam patterns.

## Why ScamShield

ScamShield exists to make this workflow practical. Fraud and scam detection engine — analyze messages for phishing, urgency tricks, and financial scam patterns. It favours a small, inspectable surface over sprawling configuration.

## Features

- CLI command `scamshield`
- `RiskScore` — exported from `src/scamshield/core.py`
- `ScamReport` — exported from `src/scamshield/core.py`
- Included test suite
- Dedicated documentation folder

## Tech Stack

- **Runtime:** Python
- **Frameworks:** Typer
- **Tooling:** Rich, Pydantic

## How It Works

The codebase is organised into `docs/`, `src/`, `tests/`. The primary entry points are `src/scamshield/core.py`, `src/scamshield/__init__.py`. `src/scamshield/core.py` exposes `RiskScore`, `ScamReport` — the core types that drive the behaviour.

## Getting Started

```bash
pip install -e .
scamshield --help
```

## Usage

```bash
scamshield --help
```

## Project Structure

```
ScamShield/
├── .env.example
├── CONTRIBUTING.md
├── Makefile
├── README.md
├── docs/
├── pyproject.toml
├── src/
├── tests/
```