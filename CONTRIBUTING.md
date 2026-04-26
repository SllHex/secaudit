# Contributing

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Useful Commands

```bash
pytest
ruff check .
mypy secaudit
python3 main.py --help
```

## Guidelines

- Keep checks safe and non-intrusive.
- Prefer deterministic output over clever heuristics.
- Add type hints for new public APIs.
- Add tests for new resolution, config, serialization, or scoring behavior.
- Avoid introducing network-dependent tests.

## Adding a Module

1. Create a new class in `secaudit/modules/`.
2. Extend `AuditModule`.
3. Register it in `secaudit/registry.py`.
4. Add contributor-facing metadata: category, aliases, purpose, risks, profiles.
5. Add tests if the module introduces reusable logic.

## Reporting Bugs

Please include:

- command used
- expected behavior
- actual behavior
- Python version
- sanitized output or stack trace
