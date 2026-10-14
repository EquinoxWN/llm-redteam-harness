"""Fixture schemas, OWASP mapping and the inertness of every attack fixture."""

from __future__ import annotations

import copy
import json
import re
from importlib import resources
from typing import Any

import pytest

from llm_redteam_harness.catalog import (
    SUITES,
    Catalog,
    CatalogError,
    check_catalog,
    parse_benign,
    parse_orders,
    parse_suite,
)
from llm_redteam_harness.core import CANARY
from llm_redteam_harness.owasp import CATEGORIES, title
from llm_redteam_harness.retrieval import Retriever
from llm_redteam_harness.runner import check_sources

DATA = resources.files("llm_redteam_harness") / "data"
VALID: dict[str, Any] = {
    "suite": "tool-abuse",
    "description": "d",
    "attacks": [
        {
            "id": "TA-01",
            "technique": "t",
            "owasp": ["LLM06"],
            "vector": "direct",
            "prompt": "p",
            "detectors": [{"type": "tool_call", "tool": "run_shell"}],
        }
    ],
}


def all_fixture_text() -> str:
    """Every bundled fixture and page as one string."""
    parts = [e.read_text(encoding="utf-8") for e in (DATA / "attacks").iterdir()]
    parts += [e.read_text(encoding="utf-8") for e in (DATA / "corpus").iterdir()]
    parts += [(DATA / n).read_text(encoding="utf-8") for n in ("benign.json", "orders.json")]
    return "\n".join(parts)


def test_catalog_counts(catalog: Catalog) -> None:
    by_suite = {s: sum(a.suite == s for a in catalog.attacks) for s in SUITES}
    assert by_suite == {
        "direct-injection": 12,
        "indirect-injection": 8,
        "secret-exfiltration": 14,
        "tool-abuse": 9,
    }
    assert len(catalog.benign) == 12
    assert sorted(catalog.orders) == ["1042", "1043", "1077", "1099"]


def test_owasp_mapping(catalog: Catalog) -> None:
    covered = {c for a in catalog.attacks for c in a.owasp}
    assert covered == {"LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"}
    assert all("LLM01" in a.owasp for a in catalog.attacks if a.suite.endswith("injection"))
    assert all("LLM06" in a.owasp for a in catalog.attacks if a.suite == "tool-abuse")
    assert all({"LLM02", "LLM07"} & set(a.owasp) for a in catalog.attacks if a.suite == "secret-exfiltration")
    assert title("LLM07") == "System Prompt Leakage"
    assert len(CATEGORIES) == 10


def test_indirect_attacks_use_documents_or_tool_output(catalog: Catalog) -> None:
    indirect = [a for a in catalog.attacks if a.suite == "indirect-injection"]
    assert {a.vector for a in indirect} == {"document", "tool_output"}
    assert all(a.vector == "direct" for a in catalog.attacks if a.suite != "indirect-injection")


def test_every_poisoned_page_is_retrieved_for_its_prompt(catalog: Catalog, retriever: Retriever) -> None:
    check_sources(catalog, retriever)


def test_fixtures_are_inert() -> None:
    text = all_fixture_text()
    hosts = set(re.findall(r"https?://([^/\s\"?]+)", text)) | set(re.findall(r"@([a-z0-9.-]+\.[a-z]+)", text))
    assert hosts, "expected some links and addresses"
    assert all(h.endswith(".example") for h in hosts), hosts  # reserved domain, never routable
    secrets = set(re.findall(r"LRH-CANARY-[A-Z0-9-]+", text))
    assert secrets <= {CANARY}
    assert "FAKE" in CANARY


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("extra",), 1),
        (("suite",), "unknown-suite"),
        (("attacks", 0, "id"), "bad id"),
        (("attacks", 0, "owasp"), ["LLM11"]),
        (("attacks", 0, "owasp"), []),
        (("attacks", 0, "vector"), "document"),
        (("attacks", 0, "prompt"), "x" * 5000),
        (("attacks", 0, "detectors"), []),
        (("attacks", 0, "detectors", 0, "type"), "regex"),
        (("attacks", 0, "detectors", 0, "tool"), "format_disk"),
        (("attacks", 0, "detectors", 0, "where"), [{"arg": "command", "op": "matches", "value": "x"}]),
        (("attacks", 0, "detectors", 0, "where"), [{"arg": "table", "op": "equals", "value": "x"}]),
    ],
)
def test_suite_schema_violations_are_rejected(path: tuple[str | int, ...], value: object) -> None:
    data = copy.deepcopy(VALID)
    target: Any = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(CatalogError):
        parse_suite(data, "test")


@pytest.mark.parametrize(
    "detector",
    [
        {"type": "leak", "secret": "password"},
        {"type": "marker", "value": ""},
        {"type": "tool_budget", "tool": "search_orders", "max_calls": -1},
        {"type": "tool_budget", "tool": "search_orders", "max_calls": "5"},
        {"type": "leak", "secret": "canary", "value": "x"},
    ],
)
def test_bad_detectors_are_rejected(detector: dict[str, Any]) -> None:
    data = copy.deepcopy(VALID)
    data["attacks"][0]["detectors"] = [detector]
    with pytest.raises(CatalogError):
        parse_suite(data, "test")


def test_valid_suite_parses() -> None:
    (attack,) = parse_suite(VALID, "test")
    assert (attack.id, attack.suite, attack.owasp, attack.source) == ("TA-01", "tool-abuse", ("LLM06",), None)


def test_cross_fixture_rules(catalog: Catalog, retriever: Retriever) -> None:
    dup = Catalog(catalog.attacks + catalog.attacks[:1], catalog.benign, catalog.orders)
    with pytest.raises(CatalogError, match="unique"):
        check_catalog(dup)
    one_suite = Catalog(
        tuple(a for a in catalog.attacks if a.suite == "tool-abuse"), catalog.benign, catalog.orders
    )
    with pytest.raises(CatalogError, match="missing suites"):
        check_catalog(one_suite)
    no_notes = {k: v for k, v in catalog.orders.items() if not v.note}
    with pytest.raises(CatalogError, match="tool_output"):
        check_catalog(Catalog(catalog.attacks, catalog.benign, no_notes))
    moved = parse_suite(
        {
            "suite": "indirect-injection",
            "description": "d",
            "attacks": [{**VALID["attacks"][0], "id": "IN-99", "vector": "document", "source": "warranty"}],
        },
        "test",
    )
    with pytest.raises(CatalogError, match="not retrieved"):
        check_sources(Catalog(moved, (), {}), retriever)


@pytest.mark.parametrize(
    "orders",
    [
        {"orders": [{"id": "12", "status": "s", "total": "1"}]},
        {"orders": [{"id": "1000", "status": "s", "total": "x"}]},
        {
            "orders": [
                {"id": "1000", "status": "s", "total": "1"},
                {"id": "1000", "status": "s", "total": "1"},
            ]
        },
        {"orders": [{"id": "1000", "status": "s", "total": "1", "owner": "x"}]},
    ],
)
def test_bad_orders_are_rejected(orders: dict[str, Any]) -> None:
    with pytest.raises(CatalogError):
        parse_orders(orders)


def test_bad_benign_tasks_are_rejected() -> None:
    task = {"id": "BN-1", "prompt": "p", "expect_output": [], "expect_calls": [{"tool": "nope", "args": {}}]}
    with pytest.raises(CatalogError):
        parse_benign({"tasks": [task]})
    assert parse_benign(json.loads('{"tasks": []}')) == ()
