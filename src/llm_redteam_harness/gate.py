"""Regression gate: fail CI when the hardened agent gets worse than its committed baseline.

The gate also fails when the weak agent's success rate drops below its floor: the weak agent is
the harness's own control, and if attacks stop landing on it, a detector or fixture is broken.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

BASELINE_SCHEMA: Final = 1
MAX_BASELINE_BYTES: Final = 64 * 1024
KEYS: Final = {
    "schema",
    "agent",
    "max_attack_success_rate",
    "max_by_suite",
    "max_by_owasp",
    "allowed_successes",
    "min_utility",
    "weak_min_attack_success_rate",
}
EPS: Final = 1e-9


class BaselineError(ValueError):
    """A baseline file does not match its schema."""


def make_baseline(report: dict[str, Any], agent: str = "hardened") -> dict[str, Any]:
    """A baseline that accepts exactly the current results and nothing worse."""
    a, weak = report["agents"][agent], report["agents"]["weak"]
    return {
        "schema": BASELINE_SCHEMA,
        "agent": agent,
        "max_attack_success_rate": a["attack_success_rate"]["rate"],
        "max_by_suite": {k: v["rate"] for k, v in a["by_suite"].items()},
        "max_by_owasp": {k: v["rate"] for k, v in a["by_owasp"].items()},
        "allowed_successes": sorted(a["successful_attacks"]),
        "min_utility": a["utility"]["rate"],
        "weak_min_attack_success_rate": weak["attack_success_rate"]["rate"],
    }


def load_baseline(path: Path) -> dict[str, Any]:
    """Read and validate a baseline file."""
    raw = path.read_bytes()
    if len(raw) > MAX_BASELINE_BYTES:
        raise BaselineError(f"{path} is larger than {MAX_BASELINE_BYTES} bytes")
    data = json.loads(raw)
    if not isinstance(data, dict) or set(data) != KEYS or data["schema"] != BASELINE_SCHEMA:
        raise BaselineError(f"{path}: baseline must have exactly the keys {sorted(KEYS)} and schema 1")
    return data


def check(report: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    """Every way the report is worse than the baseline; empty means the gate passes."""
    agents = report["agents"]
    name = baseline["agent"]
    if name not in agents or "weak" not in agents:
        return [f"report must contain the weak and {name} agents"]
    a = agents[name]
    problems = []
    overall = a["attack_success_rate"]["rate"]
    if overall > baseline["max_attack_success_rate"] + EPS:
        problems.append(
            f"{name} attack success rate {overall} > baseline {baseline['max_attack_success_rate']}"
        )
    for group in ("by_suite", "by_owasp"):
        limits = baseline[f"max_{group}"]
        for key, value in a[group].items():
            if key not in limits:
                problems.append(f"{group} {key} is not in the baseline (new suite or category: update it)")
            elif value["rate"] > limits[key] + EPS:
                problems.append(f"{name} {group} {key}: {value['rate']} > baseline {limits[key]}")
    new = sorted(set(a["successful_attacks"]) - set(baseline["allowed_successes"]))
    if new:
        problems.append(f"{name}: attacks that now succeed: {', '.join(new)}")
    if a["utility"]["rate"] < baseline["min_utility"] - EPS:
        problems.append(f"{name} utility {a['utility']['rate']} < baseline {baseline['min_utility']}")
    weak = agents["weak"]["attack_success_rate"]["rate"]
    if weak < baseline["weak_min_attack_success_rate"] - EPS:
        problems.append(
            f"weak agent attack success rate {weak} < floor {baseline['weak_min_attack_success_rate']}: "
            "a detector or fixture may be broken"
        )
    return problems
