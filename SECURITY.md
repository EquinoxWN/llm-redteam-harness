# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**Security > Report a vulnerability** on this repository
(`https://github.com/EquinoxWN/llm-redteam-harness/security/advisories/new`). Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. You will get an answer
within 7 days. Fixes are released as soon as they are ready, and you are credited unless you ask
not to be.

## Supported versions

This project is pre-1.0. Only the latest commit on `main` receives fixes.

## Scope

- **In scope:** a fake tool that could reach anything outside the process, a fixture or detector
  that could leak or execute content, unbounded input that could exhaust memory or time, a gate
  that passes a regression, and anything in the attack fixtures that is not inert.
- **Out of scope:** a new prompt that beats the sample agent's guardrails. That is a measurement:
  please open a pull request that adds it to a suite (with an updated baseline) instead.

## How this repository protects itself

- Attack fixtures are inert text; the planted secret is a clearly fake canary and every host is on
  the reserved `.example` domain, both checked by tests. No external model API is called.
- The fake tools only record calls; a test checks their module imports nothing that could reach the
  file system, network or a shell.
- Every GitHub Action is pinned to a full commit SHA, and workflows run with read-only
  permissions and without persisted credentials.
- Dependabot update pull requests are paused (`open-pull-requests-limit: 0`) so the repository keeps a single `main` branch; dependencies are updated by hand and checked by the CI audit.
- CI runs lint, tests, the red-team regression gate and a known-vulnerability check (pip-audit) on
  every push and pull request.
