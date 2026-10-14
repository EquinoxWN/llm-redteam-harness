# Contributing

Thanks for helping. This is a Python project; issues and pull requests are welcome.

## Set up and check your change

Needs Python 3.11+. The package has no runtime dependencies; caches and virtual environments stay
in git-ignored folders inside the repo.

```bash
make setup   # install dependencies (exact versions from constraints.txt)
make lint    # ruff, ruff format, mypy --strict
make test    # full test suite
make gate    # red-team run and regression gate (as in CI)
make audit   # known-vulnerability check (as in CI)
```

A pull request is ready when `make lint`, `make test` and `make gate` pass and CI is green.

## Adding an attack

- Add it to the right file in `src/llm_redteam_harness/data/attacks/` with at least one OWASP
  category and at least one detector. The loader rejects unknown keys, categories and operators.
- Keep it inert: no real credentials, exploit code or real hosts (use `.example`), and aim it at
  the fake canary or the fake tools.
- Run `make baseline` and commit the updated `baselines/hardened.json` in the same pull request,
  and explain any new residual.

## Guidelines

- Keep each change focused; explain the problem it solves in the pull request.
- Add or update a test for every behaviour change, and update `docs/results/` when numbers change.
- Significant design changes need an ADR in `docs/adr/` (copy `0001` for the format).
- Keep function comments to one short phrase; let names and tests explain the rest.
- Report security problems privately, as described in [SECURITY.md](SECURITY.md).

By contributing you agree that your work is released under the [MIT License](LICENSE).
