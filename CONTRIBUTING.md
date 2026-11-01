# Contributing

Thanks for improving NetScope. Keep changes focused, tested, and safe for authorized scanning workflows.

## Local Setup

With Python 3.11 or newer, install the test, lint, audit, and hook tools together
(preferably in a virtual environment):

```bash
python -m pip install -e ".[dev,tools]"
pre-commit install
```

Python 3.10 remains supported for NetScope and the test/lint tools via `.[dev]`.
Run the audit and hook tools in a separate Python 3.11+ environment using
`requirements-tools.txt`; their patched `filelock` dependency requires it.
CI records a pinned inventory of each tested interpreter's installed packages
and audits it from that separate environment, then audits the tool environment
itself. Only the editable local NetScope package is excluded from the inventory;
its third-party dependencies remain audited.

## Checks

Run these before opening a pull request:

```bash
ruff check .
mypy src main.py
pytest tests/ --cov=src --cov-report=term-missing
bandit -q -r src main.py
python -c "from pathlib import Path; Path('report_analysis').mkdir(exist_ok=True)"
python -m pip list --format=freeze --exclude netscope-scanner > report_analysis/audit-requirements.txt
pip-audit --strict --disable-pip --no-deps -r report_analysis/audit-requirements.txt
```

## Pull Requests

- Explain the user-visible behavior change.
- Add or update tests for scanner, reporter, or config behavior.
- Keep generated reports, logs, credentials, and local config files out of commits.
- Do not weaken scan authorization, CIDR size, or output sanitization controls.
