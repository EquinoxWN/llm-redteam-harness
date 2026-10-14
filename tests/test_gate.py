"""The regression gate: passes on the committed baseline, fails on every kind of regression."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from llm_redteam_harness.catalog import Catalog
from llm_redteam_harness.gate import BaselineError, check, load_baseline, make_baseline
from llm_redteam_harness.guardrails import Guardrails
from llm_redteam_harness.report import build_report
from llm_redteam_harness.retrieval import Retriever
from llm_redteam_harness.runner import AgentRun, run_agent

COMMITTED = Path(__file__).resolve().parents[1] / "baselines" / "hardened.json"


@pytest.fixture(scope="module")
def report(weak_run: AgentRun, hardened_run: AgentRun) -> dict[str, Any]:
    """The report CI produces."""
    return build_report([weak_run, hardened_run])


def test_committed_baseline_matches_current_results(report: dict[str, Any]) -> None:
    baseline = load_baseline(COMMITTED)
    assert check(report, baseline) == []
    assert baseline == make_baseline(report)


def test_gate_fails_when_a_defence_is_removed(
    catalog: Catalog, retriever: Retriever, weak_run: AgentRun, report: dict[str, Any]
) -> None:
    weaker = run_agent("hardened", Guardrails.all_on().without("tool_policy"), catalog, retriever=retriever)
    problems = check(build_report([weak_run, weaker]), make_baseline(report))
    assert any("attacks that now succeed: TA-03" in p for p in problems)
    assert any(p.startswith("hardened by_suite tool-abuse") for p in problems)
    assert any(p.startswith("hardened attack success rate") for p in problems)


def test_gate_fails_on_a_swapped_success_with_the_same_rate(report: dict[str, Any]) -> None:
    changed = copy.deepcopy(report)
    ids = changed["agents"]["hardened"]["successful_attacks"]
    ids[ids.index("DI-07")] = "TA-01"
    assert check(changed, make_baseline(report)) == ["hardened: attacks that now succeed: TA-01"]


def test_gate_fails_when_utility_drops(report: dict[str, Any]) -> None:
    changed = copy.deepcopy(report)
    changed["agents"]["hardened"]["utility"]["rate"] = 11 / 12
    assert check(changed, make_baseline(report)) == ["hardened utility 0.9166666666666666 < baseline 1.0"]


def test_gate_fails_when_the_weak_control_stops_failing(report: dict[str, Any]) -> None:
    changed = copy.deepcopy(report)
    changed["agents"]["weak"]["attack_success_rate"]["rate"] = 0.5
    (problem,) = check(changed, make_baseline(report))
    assert "a detector or fixture may be broken" in problem


def test_gate_fails_on_an_unknown_suite_or_missing_agent(report: dict[str, Any]) -> None:
    changed = copy.deepcopy(report)
    changed["agents"]["hardened"]["by_suite"]["new-suite"] = {"successes": 0, "attempts": 1, "rate": 0.0}
    assert check(changed, make_baseline(report)) == [
        "by_suite new-suite is not in the baseline (new suite or category: update it)"
    ]
    del changed["agents"]["weak"]
    assert check(changed, make_baseline(report)) == ["report must contain the weak and hardened agents"]


def test_improvements_pass(report: dict[str, Any]) -> None:
    changed = copy.deepcopy(report)
    hardened = changed["agents"]["hardened"]
    hardened["successful_attacks"] = []
    hardened["attack_success_rate"]["rate"] = 0.0
    for group in ("by_suite", "by_owasp"):
        for value in hardened[group].values():
            value["rate"] = 0.0
    assert check(changed, make_baseline(report)) == []


def test_bad_baseline_files_are_rejected(tmp_path: Path, report: dict[str, Any]) -> None:
    good = make_baseline(report)
    cases = [{**good, "extra": 1}, {**good, "schema": 2}, [1, 2]]
    for i, data in enumerate(cases):
        path = tmp_path / f"b{i}.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(BaselineError):
            load_baseline(path)
    big = tmp_path / "big.json"
    big.write_text(" " * 70_000, encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(big)
