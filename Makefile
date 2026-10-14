.PHONY: setup lint test run gate baseline audit clean ci

PY ?= python

setup:
	$(PY) -m pip install --upgrade pip && $(PY) -m pip install -c constraints.txt -e ".[dev]"

# ruff, ruff format and mypy --strict.
lint:
	$(PY) -m ruff check . && $(PY) -m ruff format --check . && $(PY) -m mypy

# 184 tests: model, retrieval, tools, guardrails, detectors, fixtures, agent, end-to-end runs, gate, CLI.
test:
	$(PY) -m pytest -q

# Every attack suite against the weak and the hardened agent; full report in .tmp/.
run:
	lrh run --json .tmp/report.json --markdown .tmp/report.md

# The CI regression gate: exit 1 if the hardened agent does worse than baselines/hardened.json.
gate:
	lrh run --gate baselines/hardened.json

# Accept the current results as the new baseline (a deliberate, reviewed change).
baseline:
	lrh run --write-baseline baselines/hardened.json

# Known vulnerabilities in the installed Python dependencies.
audit:
	$(PY) -m pip_audit --skip-editable --cache-dir .tmp/pip-audit

clean:
	rm -rf .tmp/report.json .tmp/report.md .tmp/pytest

ci: setup lint test gate
