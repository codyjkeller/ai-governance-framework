# Contributing

Contributions are welcome. Please follow the guidelines below.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/codyjkeller/ai-governance-framework.git
cd ai-governance-framework

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install dev dependencies
make dev
# This installs the package in editable mode with all dev + cli extras
# and sets up pre-commit hooks.
```

## Running Tests

```bash
# Run all tests with coverage
make test

# Run a specific test file
pytest tests/test_input_scanner.py -v

# Run tests matching a keyword
pytest -k "ssn" -v
```

## Code Standards

- **Linter:** Ruff (configured in `pyproject.toml`)
- **Type checker:** Mypy (strict mode)
- **Formatter:** Ruff format
- **Security:** Bandit + detect-secrets pre-commit hook

Run all checks:
```bash
make lint
make security
```

Auto-format:
```bash
make format
```

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Write tests for any new functionality. Maintain >80% coverage.
3. Ensure all checks pass: `make lint && make test && make security`
4. Update `CHANGELOG.md` with your changes under the `[Unreleased]` section.
5. Open a PR against `main` with a clear description of the change.

## Adding a New Pattern

To add a new regex detection pattern:

1. Add the `PatternDefinition` to `src/ai_governance/scanning/patterns.py` in the appropriate dict (`INPUT_PATTERNS` or `OUTPUT_PATTERNS`).
2. Add a corresponding rule to `policies/generative_ai_aup.yaml` under `data_rules`.
3. Add at least one true-positive and one true-negative test in the appropriate test file.
4. Document false-positive and false-negative risks in the `PatternDefinition`.

## Adding a New Scanner

To add a non-regex scanner (e.g., ML-based NER):

1. Create a new module in `src/ai_governance/scanning/`.
2. Implement the `BaseScanner` interface from `scanning/base.py`.
3. Wire it into the server alongside the existing scanners.
4. Add tests.
