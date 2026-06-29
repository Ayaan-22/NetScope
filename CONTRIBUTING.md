# Contributing

Thanks for improving NetScope. Keep changes focused, tested, and safe for authorized scanning workflows.

## Local Setup

```bash
python -m pip install -e ".[dev]"
pre-commit install
```

## Checks

Run these before opening a pull request:

```bash
ruff check .
mypy src main.py
pytest tests/ --cov=src --cov-report=term-missing
bandit -q -r src main.py
pip-audit -r requirements.txt -r requirements-dev.txt
```

## Pull Requests

- Explain the user-visible behavior change.
- Add or update tests for scanner, reporter, or config behavior.
- Keep generated reports, logs, credentials, and local config files out of commits.
- Do not weaken scan authorization, CIDR size, or output sanitization controls.
