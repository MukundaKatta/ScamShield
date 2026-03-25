# Contributing to ScamShield

We welcome contributions! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/MukundaKatta/ScamShield.git
cd ScamShield
pip install -e ".[dev]"
```

## Running Tests

```bash
make test
# or directly:
python -m pytest tests/ -v
```

## Linting

```bash
make lint
make fmt
```

## Adding New Detection Patterns

1. Open `src/scamshield/config.py`
2. Add patterns to the appropriate list (e.g., `urgency_phrases`, `financial_keywords`)
3. Add tests in `tests/test_core.py` to verify detection
4. Submit a pull request

## Adding a New Detection Category

1. Add the pattern list to `DetectionConfig` in `config.py`
2. Add a weight entry in `category_weights`
3. Add scoring logic in `ScamDetector.analyze()` in `core.py`
4. Update `classify_scam_type()` in `utils.py`
5. Write tests and update `docs/ARCHITECTURE.md`

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include tests for new features
- Ensure all existing tests pass
- Follow the existing code style (enforced by ruff)

## Code of Conduct

Be respectful and constructive. We're all here to make the internet safer.
