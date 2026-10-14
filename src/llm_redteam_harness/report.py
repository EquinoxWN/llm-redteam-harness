"""Turn agent runs into a JSON report, a Markdown summary and a console table."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any, Final

from llm_redteam_harness.catalog import SUITES
from llm_redteam_harness.owasp import CATEGORIES
from llm_redteam_harness.runner import AgentRun, Rate

SCHEMA: Final = 1
EXCERPT: Final = 240
STAND_IN_NOTE: Final = (
    "The target model is a deterministic rule-based stand-in (scripted-v1), not a language model; "
    "rates describe this sample agent only."
)


def rate(r: Rate) -> dict[str, Any]:
    """A rate as JSON."""
    return {"successes": r.successes, "attempts": r.attempts, "rate": round(r.value, 4)}


def pct(r: Rate) -> str:
    """'3/12 (25.0%)'."""
    return f"{r.successes}/{r.attempts} ({100 * r.value:.1f}%)"


def agent_json(run: AgentRun) -> dict[str, Any]:
    """One agent's results as JSON."""
    return {
        "guardrails": list(run.guardrails.enabled()),
        "attack_success_rate": rate(run.overall()),
        "model_fooled_rate": rate(run.fooled()),
        "by_suite": {k: rate(v) for k, v in run.by_suite().items()},
        "by_owasp": {k: rate(v) for k, v in run.by_owasp().items()},
        "utility": rate(run.utility()),
        "successful_attacks": list(run.successful_ids()),
        "failed_benign": [
            {"id": b.task.id, "problems": list(b.problems)} for b in run.benign if not b.passed
        ],
        "attacks": [
            {
                "id": r.attack.id,
                "suite": r.attack.suite,
                "owasp": list(r.attack.owasp),
                "success": r.success,
                "model_fooled": r.model_fooled,
                "evidence": list(r.evidence),
                "input_blocked": r.transcript.input_blocked,
                "tool_calls_run": len(r.transcript.executed),
                "tool_calls_blocked": len(r.transcript.blocked),
                "output_filtered": list(r.transcript.output_filtered),
                "output": r.transcript.output[:EXCERPT],
            }
            for r in run.attacks
        ],
    }


def build_report(runs: Sequence[AgentRun]) -> dict[str, Any]:
    """The full JSON report for one or more agents run on the same catalog."""
    first = runs[0]
    covered = sorted({c for r in first.attacks for c in r.attack.owasp})
    suites = {s: sum(1 for r in first.attacks if r.attack.suite == s) for s in SUITES}
    return {
        "schema": SCHEMA,
        "model": first.model,
        "note": STAND_IN_NOTE,
        "catalog": {
            "attacks": len(first.attacks),
            "benign_tasks": len(first.benign),
            "suites": suites,
            "owasp_covered": covered,
            "owasp_not_covered": [c for c in CATEGORIES if c not in covered],
        },
        "agents": {run.name: agent_json(run) for run in runs},
    }


def result_line(runs: Sequence[AgentRun], gate: str | None = None) -> str:
    """One line for CI annotations and logs."""
    parts = [f"{r.name} ASR {pct(r.overall())}, utility {pct(r.utility())}" for r in runs]
    return "RESULT " + "; ".join(parts) + (f"; gate {gate}" if gate else "")


def console_table(runs: Sequence[AgentRun]) -> str:
    """Attack success rate per suite and per OWASP category, one column per agent."""

    def row(label: str, rates: Sequence[Rate]) -> str:
        """One aligned line."""
        return f"{label[:43]:44}" + "".join(f"{pct(r):>18}" for r in rates)

    head = "".join(f"{r.name + ' ASR':>18}" for r in runs)
    suites, owasp = [r.by_suite() for r in runs], [r.by_owasp() for r in runs]
    lines = [STAND_IN_NOTE, "", f"{'':44}{head}"]
    lines += [row(s, [x[s] for x in suites]) for s in SUITES]
    lines += [
        row("all attacks", [r.overall() for r in runs]),
        row("model fooled (before agent checks)", [r.fooled() for r in runs]),
        row("benign tasks handled (utility)", [r.utility() for r in runs]),
        "",
        f"{'OWASP Top 10 for LLM Apps (2025)':44}{head}",
    ]
    lines += [row(f"{c} {CATEGORIES[c]}", [x[c] for x in owasp]) for c in sorted(owasp[0])]
    for r in runs:
        lines += ["", f"{r.name}: successful attacks: {', '.join(r.successful_ids()) or 'none'}"]
    return "\n".join(lines)


def markdown(runs: Sequence[AgentRun]) -> str:
    """The same results as Markdown tables."""

    def row(label: str, attempts: int, cells: Iterable[str]) -> str:
        """One table row."""
        return f"| {label} | {attempts} | " + " | ".join(cells) + " |"

    head = " | ".join(f"{r.name} ASR" for r in runs)
    rule = "|---|---|" + "---|" * len(runs)
    suites, owasp = [r.by_suite() for r in runs], [r.by_owasp() for r in runs]
    out = [f"> {STAND_IN_NOTE}", "", f"| Suite | Attacks | {head} |", rule]
    out += [row(s, suites[0][s].attempts, (pct(x[s]) for x in suites)) for s in SUITES]
    out.append(row("**all**", runs[0].overall().attempts, (f"**{pct(r.overall())}**" for r in runs)))
    out.append(row("benign tasks handled", runs[0].utility().attempts, (pct(r.utility()) for r in runs)))
    out += ["", f"| OWASP category | Attacks | {head} |", rule]
    out += [
        row(f"{c} {CATEGORIES[c]}", owasp[0][c].attempts, (pct(x[c]) for x in owasp))
        for c in sorted(owasp[0])
    ]
    return "\n".join(out) + "\n"
