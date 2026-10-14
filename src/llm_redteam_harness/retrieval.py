"""A small local document set and a deterministic BM25 retriever over it."""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from importlib import resources
from typing import Final

MAX_DOC_CHARS: Final = 20_000
MAX_DOCS: Final = 500
DOC_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_WORD = re.compile(r"[a-z0-9]+")
_STOP: Final = frozenset(
    (
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "can",
        "do",
        "does",
        "for",
        "from",
        "how",
        "i",
        "if",
        "in",
        "is",
        "it",
        "its",
        "my",
        "of",
        "on",
        "or",
        "so",
        "that",
        "the",
        "this",
        "to",
        "was",
        "what",
        "when",
        "where",
        "which",
        "will",
        "with",
        "you",
        "your",
    )
)


class CorpusError(ValueError):
    """A document is missing, malformed or too large."""


@dataclass(frozen=True, slots=True)
class Document:
    """One knowledge-base page: id (file stem), title and body text."""

    id: str
    title: str
    body: str


def stem(word: str) -> str:
    """Crude suffix stripping so 'returned' and 'returns' match 'return'."""
    for suffix in ("ing", "ed", "es", "s"):
        if len(word) > len(suffix) + 3 and word.endswith(suffix):
            return word[: -len(suffix)]
    return word


def terms(text: str) -> list[str]:
    """Lowercased, stemmed content words of a text."""
    return [stem(w) for w in _WORD.findall(text.lower()) if w not in _STOP]


def parse_document(doc_id: str, text: str) -> Document:
    """Validate one Markdown page whose first line is '# Title'."""
    if not DOC_ID.match(doc_id):
        raise CorpusError(f"invalid document id: {doc_id!r}")
    if len(text) > MAX_DOC_CHARS:
        raise CorpusError(f"document {doc_id} is longer than {MAX_DOC_CHARS} characters")
    first, _, body = text.replace("\r\n", "\n").partition("\n")
    if not first.startswith("# ") or not first[2:].strip():
        raise CorpusError(f"document {doc_id} must start with '# Title'")
    return Document(doc_id, first[2:].strip(), body.strip())


def load_corpus() -> tuple[Document, ...]:
    """The bundled sample knowledge base, sorted by id."""
    root = resources.files("llm_redteam_harness") / "data" / "corpus"
    docs = [
        parse_document(entry.name.removesuffix(".md"), entry.read_text(encoding="utf-8"))
        for entry in root.iterdir()
        if entry.name.endswith(".md")
    ]
    if not docs or len(docs) > MAX_DOCS:
        raise CorpusError(f"corpus must hold 1 to {MAX_DOCS} documents, found {len(docs)}")
    return tuple(sorted(docs, key=lambda d: d.id))


class Retriever:
    """Okapi BM25 over title and body; ties broken by document id."""

    def __init__(self, docs: Iterable[Document], k1: float = 1.5, b: float = 0.75) -> None:
        """Index the documents."""
        self.docs: tuple[Document, ...] = tuple(docs)
        ids = [d.id for d in self.docs]
        if len(set(ids)) != len(ids):
            raise CorpusError("duplicate document ids")
        self._tf = [Counter(terms(f"{d.title} {d.title} {d.body}")) for d in self.docs]
        self._len = [sum(tf.values()) for tf in self._tf]
        self._avg = sum(self._len) / max(len(self._len), 1)
        df: Counter[str] = Counter()
        for tf in self._tf:
            df.update(tf.keys())
        n = len(self.docs)
        self._idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}
        self.k1, self.b = k1, b

    def score(self, query: str) -> list[tuple[float, Document]]:
        """BM25 score of every document for the query, best first."""
        q = terms(query)
        scored: list[tuple[float, Document]] = []
        for doc, tf, length in zip(self.docs, self._tf, self._len, strict=True):
            s = 0.0
            for t in q:
                f = tf.get(t, 0)
                if f:
                    norm = f + self.k1 * (1 - self.b + self.b * length / self._avg)
                    s += self._idf[t] * f * (self.k1 + 1) / norm
            scored.append((s, doc))
        scored.sort(key=lambda p: (-p[0], p[1].id))
        return scored

    def top(self, query: str, k: int = 2) -> Sequence[Document]:
        """The k best documents with a positive score."""
        return [doc for s, doc in self.score(query)[:k] if s > 0]

    def get(self, doc_id: str) -> Document:
        """A document by id."""
        for doc in self.docs:
            if doc.id == doc_id:
                return doc
        raise CorpusError(f"unknown document: {doc_id}")
