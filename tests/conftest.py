"""Shared fixtures: the catalog, the retriever and one run of each agent per session."""

from __future__ import annotations

import pytest
from hypothesis import settings

from llm_redteam_harness.agent import Agent
from llm_redteam_harness.catalog import Catalog, load_catalog
from llm_redteam_harness.guardrails import Guardrails
from llm_redteam_harness.model import ScriptedModel
from llm_redteam_harness.retrieval import Retriever, load_corpus
from llm_redteam_harness.runner import AGENTS, AgentRun, run_agent

# Reproducible property tests that write nothing to disk.
settings.register_profile("repo", database=None, derandomize=True, deadline=None, max_examples=200)
settings.load_profile("repo")


@pytest.fixture(scope="session")
def catalog() -> Catalog:
    """All bundled fixtures."""
    return load_catalog()


@pytest.fixture(scope="session")
def retriever() -> Retriever:
    """BM25 over the bundled pages."""
    return Retriever(load_corpus())


@pytest.fixture(scope="session")
def weak_run(catalog: Catalog, retriever: Retriever) -> AgentRun:
    """Every attack against the weak agent, once per session."""
    return run_agent("weak", AGENTS["weak"], catalog, retriever=retriever)


@pytest.fixture(scope="session")
def hardened_run(catalog: Catalog, retriever: Retriever) -> AgentRun:
    """Every attack against the hardened agent, once per session."""
    return run_agent("hardened", AGENTS["hardened"], catalog, retriever=retriever)


def make_agent(catalog: Catalog, retriever: Retriever, guardrails: Guardrails) -> Agent:
    """An agent over the bundled data with the given defences."""
    return Agent(ScriptedModel(), retriever, catalog.orders, guardrails)
