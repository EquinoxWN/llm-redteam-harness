"""Load and validate the attack suites, benign tasks and sample orders (JSON fixtures).

Every fixture is checked against a strict schema at load time (exact keys, known OWASP ids,
known detector types and operators, unique ids, bounded sizes), so a typo in a suite fails the
run instead of silently dropping an attack.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from importlib import resources
from typing import Any, Final, Literal

from llm_redteam_harness.detectors import (
    OPS,
    SECRETS,
    Condition,
    Detector,
    Leak,
    Marker,
    ToolBudget,
    ToolCalled,
)
from llm_redteam_harness.owasp import CATEGORIES
from llm_redteam_harness.tools import SPECS, Order

SUITES: Final = ("direct-injection", "indirect-injection", "secret-exfiltration", "tool-abuse")
MAX_FIXTURE_BYTES: Final = 256 * 1024
MAX_PROMPT_CHARS: Final = 4_000
ATTACK_ID = re.compile(r"^[A-Z]{2}-\d{2}$")
ORDER_ID = re.compile(r"^\d{4}$")
Vector = Literal["direct", "document", "tool_output"]


class CatalogError(ValueError):
    """A fixture does not match its schema."""


@dataclass(frozen=True, slots=True)
class Attack:
    """One inert attack case: the prompt, how it is delivered and how success is detected."""

    id: str
    suite: str
    technique: str
    owasp: tuple[str, ...]
    vector: Vector
    source: str | None
    prompt: str
    detectors: tuple[Detector, ...]


@dataclass(frozen=True, slots=True)
class ExpectedCall:
    """A tool call a benign task needs, with the arguments that must match."""

    tool: str
    args: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class BenignTask:
    """A normal request the agent must still handle (measures over-blocking)."""

    id: str
    prompt: str
    expect_output: tuple[str, ...]
    expect_calls: tuple[ExpectedCall, ...]


@dataclass(frozen=True, slots=True)
class Catalog:
    """All fixtures the harness runs."""

    attacks: tuple[Attack, ...]
    benign: tuple[BenignTask, ...]
    orders: dict[str, Order]


def _keys(obj: Any, where: str, required: set[str], optional: frozenset[str] = frozenset()) -> dict[str, Any]:
    """Check an object has exactly the allowed keys."""
    if not isinstance(obj, dict):
        raise CatalogError(f"{where}: expected an object")
    missing, unknown = required - obj.keys(), obj.keys() - required - optional
    if missing or unknown:
        raise CatalogError(f"{where}: missing {sorted(missing)} unknown {sorted(unknown)}")
    return obj


def _text(value: Any, where: str, limit: int = MAX_PROMPT_CHARS) -> str:
    """A non-empty bounded string."""
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise CatalogError(f"{where}: expected a non-empty string of at most {limit} characters")
    return value


def _detector(obj: Any, where: str) -> Detector:
    """One detector from its JSON form."""
    kind = _keys(obj, where, {"type"}, frozenset({"secret", "value", "tool", "where", "max_calls"})).get(
        "type"
    )
    if kind == "leak":
        _keys(obj, where, {"type", "secret"})
        if obj["secret"] not in SECRETS:
            raise CatalogError(f"{where}: secret must be one of {sorted(SECRETS)}")
        return Leak(obj["secret"])
    if kind == "marker":
        _keys(obj, where, {"type", "value"})
        return Marker(_text(obj["value"], where, 200))
    if kind == "tool_call":
        _keys(obj, where, {"type", "tool"}, frozenset({"where"}))
        tool = obj["tool"]
        if tool not in SPECS:
            raise CatalogError(f"{where}: unknown tool {tool!r}")
        conditions = []
        for i, c in enumerate(obj.get("where", [])):
            _keys(c, f"{where}.where[{i}]", {"arg", "op", "value"})
            if c["op"] not in OPS or c["arg"] not in SPECS[tool].params:
                raise CatalogError(f"{where}.where[{i}]: bad op or argument")
            conditions.append(Condition(c["arg"], c["op"], _text(c["value"], where, 200)))
        return ToolCalled(tool, tuple(conditions))
    if kind == "tool_budget":
        _keys(obj, where, {"type", "tool", "max_calls"})
        if obj["tool"] not in SPECS or not isinstance(obj["max_calls"], int) or obj["max_calls"] < 0:
            raise CatalogError(f"{where}: bad tool budget")
        return ToolBudget(obj["tool"], obj["max_calls"])
    raise CatalogError(f"{where}: unknown detector type {kind!r}")


def parse_suite(data: Any, name: str) -> tuple[Attack, ...]:
    """Attacks of one suite file."""
    _keys(data, name, {"suite", "description", "attacks"})
    suite = data["suite"]
    if suite not in SUITES:
        raise CatalogError(f"{name}: unknown suite {suite!r}")
    _text(data["description"], name)
    if not isinstance(data["attacks"], list) or not data["attacks"]:
        raise CatalogError(f"{name}: attacks must be a non-empty list")
    attacks = []
    for i, a in enumerate(data["attacks"]):
        where = f"{name}.attacks[{i}]"
        _keys(a, where, {"id", "technique", "owasp", "vector", "prompt", "detectors"}, frozenset({"source"}))
        if not ATTACK_ID.match(str(a["id"])):
            raise CatalogError(f"{where}: id must look like AB-01")
        owasp = a["owasp"]
        if not isinstance(owasp, list) or not owasp or any(c not in CATEGORIES for c in owasp):
            raise CatalogError(f"{where}: owasp must list known categories")
        vector, source = a["vector"], a.get("source")
        if vector not in ("direct", "document", "tool_output") or (vector == "direct") != (source is None):
            raise CatalogError(f"{where}: direct attacks have no source, the others need one")
        if not isinstance(a["detectors"], list) or not a["detectors"]:
            raise CatalogError(f"{where}: at least one detector is required")
        detectors = tuple(_detector(d, f"{where}.detectors[{j}]") for j, d in enumerate(a["detectors"]))
        attacks.append(
            Attack(
                a["id"],
                suite,
                _text(a["technique"], where, 120),
                tuple(owasp),
                vector,
                source,
                _text(a["prompt"], where),
                detectors,
            )
        )
    return tuple(attacks)


def parse_benign(data: Any) -> tuple[BenignTask, ...]:
    """Benign tasks from their JSON form."""
    _keys(data, "benign", {"tasks"})
    tasks = []
    for i, t in enumerate(data["tasks"]):
        where = f"benign.tasks[{i}]"
        _keys(t, where, {"id", "prompt", "expect_output", "expect_calls"})
        calls = []
        for j, c in enumerate(t["expect_calls"]):
            _keys(c, f"{where}.expect_calls[{j}]", {"tool", "args"})
            if c["tool"] not in SPECS or not isinstance(c["args"], dict):
                raise CatalogError(f"{where}: bad expected call")
            calls.append(ExpectedCall(c["tool"], tuple((str(k), str(v)) for k, v in c["args"].items())))
        expect = tuple(_text(s, where, 200) for s in t["expect_output"])
        tasks.append(BenignTask(_text(t["id"], where, 20), _text(t["prompt"], where), expect, tuple(calls)))
    return tuple(tasks)


def parse_orders(data: Any) -> dict[str, Order]:
    """The in-memory order store."""
    _keys(data, "orders", {"orders"})
    orders: dict[str, Order] = {}
    for i, o in enumerate(data["orders"]):
        where = f"orders[{i}]"
        _keys(o, where, {"id", "status", "total"}, frozenset({"note"}))
        if not ORDER_ID.match(str(o["id"])) or o["id"] in orders:
            raise CatalogError(f"{where}: ids are unique 4-digit strings")
        try:
            total = Decimal(str(o["total"]))
        except InvalidOperation as exc:
            raise CatalogError(f"{where}: bad total") from exc
        orders[o["id"]] = Order(o["id"], _text(o["status"], where, 40), total, o.get("note", ""))
    return orders


def _read_json(*parts: str) -> Any:
    """A bundled JSON fixture, size-checked before parsing."""
    entry = resources.files("llm_redteam_harness").joinpath("data", *parts)
    raw = entry.read_bytes()
    if len(raw) > MAX_FIXTURE_BYTES:
        raise CatalogError(f"{'/'.join(parts)} is larger than {MAX_FIXTURE_BYTES} bytes")
    return json.loads(raw)


def check_catalog(catalog: Catalog) -> Catalog:
    """Cross-fixture rules: unique ids, every suite present, sources that exist."""
    ids = [a.id for a in catalog.attacks] + [t.id for t in catalog.benign]
    if len(set(ids)) != len(ids):
        raise CatalogError("attack and task ids must be unique")
    missing = set(SUITES) - {a.suite for a in catalog.attacks}
    if missing:
        raise CatalogError(f"missing suites: {sorted(missing)}")
    for a in catalog.attacks:
        if a.vector == "tool_output" and (
            a.source not in catalog.orders or not catalog.orders[a.source].note
        ):
            raise CatalogError(f"{a.id}: tool_output source must be an order with a note")
    return catalog


def load_catalog() -> Catalog:
    """Every bundled fixture, validated."""
    attacks = tuple(a for s in SUITES for a in parse_suite(_read_json("attacks", f"{s}.json"), s))
    return check_catalog(
        Catalog(attacks, parse_benign(_read_json("benign.json")), parse_orders(_read_json("orders.json")))
    )
