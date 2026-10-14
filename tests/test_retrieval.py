"""The local knowledge base and the BM25 retriever."""

from __future__ import annotations

import pytest

from llm_redteam_harness.retrieval import (
    MAX_DOC_CHARS,
    CorpusError,
    Document,
    Retriever,
    load_corpus,
    parse_document,
    stem,
    terms,
)


def test_corpus_loads_eleven_pages_sorted() -> None:
    docs = load_corpus()
    assert len(docs) == 11
    assert [d.id for d in docs] == sorted(d.id for d in docs)
    assert all(d.title and d.body for d in docs)


@pytest.mark.parametrize(
    ("question", "expected"),
    [
        ("How long do I have to return an item?", "returns-policy"),
        ("How long does standard shipping take?", "shipping"),
        ("Does the warranty cover my tent?", "warranty"),
        ("How do I reset my password?", "account-faq"),
        ("What size Ridge hiking boots should I order?", "size-guide-ridge-boots"),
    ],
)
def test_top_document_answers_the_question(retriever: Retriever, question: str, expected: str) -> None:
    assert retriever.top(question, 1)[0].id == expected


def test_scores_are_deterministic_with_id_tie_break() -> None:
    docs = [Document("b", "same", "text"), Document("a", "same", "text")]
    r = Retriever(docs)
    assert [d.id for d in r.top("same text", 2)] == ["a", "b"]
    assert r.score("same") == r.score("same")


def test_no_match_returns_nothing(retriever: Retriever) -> None:
    assert retriever.top("zzzz qqqq", 2) == []


def test_stemming_and_stop_words() -> None:
    assert stem("returned") == stem("returns") == "return"
    assert stem("bus") == "bus"
    assert terms("How do I return the item?") == ["return", "item"]


@pytest.mark.parametrize(
    ("doc_id", "text"),
    [
        ("Bad Id", "# T\nbody"),
        ("../escape", "# T\nbody"),
        ("ok", "no title line"),
        ("ok", "# \nbody"),
        ("ok", "# T\n" + "x" * MAX_DOC_CHARS),
    ],
)
def test_malformed_documents_are_rejected(doc_id: str, text: str) -> None:
    with pytest.raises(CorpusError):
        parse_document(doc_id, text)


def test_duplicate_ids_and_unknown_get_are_rejected(retriever: Retriever) -> None:
    with pytest.raises(CorpusError):
        Retriever([Document("a", "t", "b"), Document("a", "t", "c")])
    with pytest.raises(CorpusError):
        retriever.get("missing")
