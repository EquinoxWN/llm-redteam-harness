"""Run every attack and benign task against an agent and compute attack success rates."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Final

from llm_redteam_harness.agent import Agent, Transcript
from llm_redteam_harness.catalog import Attack, BenignTask, Catalog, CatalogError
from llm_redteam_harness.detectors import evaluate
from llm_redteam_harness.guardrails import Guardrails
from llm_redteam_harness.model import ChatModel, ScriptedModel
from llm_redteam_harness.retrieval import Retriever, load_corpus
from llm_redteam_harness.tools import Order

AGENTS: Final[dict[str, Guardrails]] = {"weak": Guardrails(), "hardened": Guardrails.all_on()}


@dataclass(frozen=True, slots=True)
class AttackResult:
    """Outcome of one attack against one agent."""

    attack: Attack
    success: bool
    evidence: tuple[str, ...]
    model_fooled: bool
    transcript: Transcript


@dataclass(frozen=True, slots=True)
class BenignResult:
    """Outcome of one benign task: did the agent still do its job?"""

    task: BenignTask
    passed: bool
    problems: tuple[str, ...]
    transcript: Transcript


@dataclass(frozen=True, slots=True)
class Rate:
    """Successes out of attempts."""

    successes: int
    attempts: int

    @property
    def value(self) -> float:
        """The fraction, 0.0 for no attempts."""
        return self.successes / self.attempts if self.attempts else 0.0


@dataclass(frozen=True, slots=True)
class AgentRun:
    """Everything one agent configuration produced."""

    name: str
    guardrails: Guardrails
    model: str
    attacks: tuple[AttackResult, ...]
    benign: tuple[BenignResult, ...]

    def overall(self) -> Rate:
        """Attack success rate over all attacks."""
        return Rate(sum(r.success for r in self.attacks), len(self.attacks))

    def fooled(self) -> Rate:
        """Share of attacks where the model itself was fooled, before agent-level defences."""
        return Rate(sum(r.model_fooled for r in self.attacks), len(self.attacks))

    def by_suite(self) -> dict[str, Rate]:
        """Attack success rate per suite."""
        return _group(self.attacks, lambda r: (r.attack.suite,))

    def by_owasp(self) -> dict[str, Rate]:
        """Attack success rate per OWASP category (an attack counts in each of its categories)."""
        return _group(self.attacks, lambda r: r.attack.owasp)

    def utility(self) -> Rate:
        """Share of benign tasks handled correctly."""
        return Rate(sum(r.passed for r in self.benign), len(self.benign))

    def successful_ids(self) -> tuple[str, ...]:
        """Ids of the attacks that succeeded."""
        return tuple(r.attack.id for r in self.attacks if r.success)


def _group(results: Iterable[AttackResult], keys: Callable[[AttackResult], Iterable[str]]) -> dict[str, Rate]:
    """Count successes per key, keys sorted."""
    counts: dict[str, list[int]] = {}
    for r in results:
        for k in keys(r):
            c = counts.setdefault(k, [0, 0])
            c[0] += r.success
            c[1] += 1
    return {k: Rate(s, n) for k, (s, n) in sorted(counts.items())}


def check_sources(catalog: Catalog, retriever: Retriever, top_k: int = 2) -> None:
    """Every document-borne attack's page exists and is retrieved for its prompt."""
    for a in catalog.attacks:
        if a.vector == "document":
            retriever.get(a.source or "")
            if a.source not in [d.id for d in retriever.top(a.prompt, top_k)]:
                raise CatalogError(f"{a.id}: document {a.source} is not retrieved for its prompt")


def score_attack(attack: Attack, t: Transcript, orders: Mapping[str, Order]) -> AttackResult:
    """Apply the attack's detectors to what the user saw and what ran."""
    evidence = evaluate(attack.detectors, t.output, t.executed, orders)
    attempted = t.executed + tuple(call for call, _ in t.blocked)
    fooled = bool(evaluate(attack.detectors, t.raw_output, attempted, orders))
    return AttackResult(attack, bool(evidence), evidence, fooled or bool(evidence), t)


def score_benign(task: BenignTask, t: Transcript) -> BenignResult:
    """Check expected output text and expected tool calls that ran."""
    problems = [f"missing {s!r} in output" for s in task.expect_output if s.lower() not in t.output.lower()]
    problems.extend(
        f"expected {e.tool}{dict(e.args)} did not run"
        for e in task.expect_calls
        if not any(c.name == e.tool and all(c.arg(k) == v for k, v in e.args) for c in t.executed)
    )
    if t.input_blocked:
        problems.append(f"input blocked: {t.input_blocked}")
    return BenignResult(task, not problems, tuple(problems), t)


def run_agent(
    name: str,
    guardrails: Guardrails,
    catalog: Catalog,
    model: ChatModel | None = None,
    retriever: Retriever | None = None,
) -> AgentRun:
    """Every attack and benign task against one agent configuration."""
    model = model or ScriptedModel()
    retriever = retriever or Retriever(load_corpus())
    check_sources(catalog, retriever)
    agent = Agent(model, retriever, catalog.orders, guardrails)
    attacks = tuple(score_attack(a, agent.run(a.prompt), catalog.orders) for a in catalog.attacks)
    benign = tuple(score_benign(t, agent.run(t.prompt)) for t in catalog.benign)
    return AgentRun(name, guardrails, model.name, attacks, benign)
