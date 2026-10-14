"""The OWASP Top 10 for LLM Applications (2025 edition) as a closed set of ids."""

from __future__ import annotations

from typing import Final

# Identifier and title of every category; fixtures may only reference these ids.
CATEGORIES: Final[dict[str, str]] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


def title(category: str) -> str:
    """Category title, or KeyError for an unknown id."""
    return CATEGORIES[category]
