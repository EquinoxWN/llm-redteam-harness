"""Command line: run the suites, gate on a baseline, inspect one turn, list the catalog."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from llm_redteam_harness import gate
from llm_redteam_harness.agent import Agent
from llm_redteam_harness.catalog import CatalogError, load_catalog
from llm_redteam_harness.guardrails import Guardrails
from llm_redteam_harness.model import ScriptedModel
from llm_redteam_harness.owasp import CATEGORIES
from llm_redteam_harness.report import build_report, console_table, markdown, result_line
from llm_redteam_harness.retrieval import CorpusError, Retriever, load_corpus
from llm_redteam_harness.runner import AGENTS, run_agent

EXIT_OK: Final = 0
EXIT_GATE: Final = 1
EXIT_USAGE: Final = 2


def _write(path: str, text: str) -> None:
    """Write a UTF-8 text file, creating its folder."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _parser() -> argparse.ArgumentParser:
    """Argument definitions."""
    p = argparse.ArgumentParser(prog="lrh", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run every suite against the weak and hardened agents")
    run.add_argument("--json", metavar="PATH", help="write the full JSON report")
    run.add_argument("--markdown", metavar="PATH", help="write Markdown tables")
    run.add_argument("--gate", metavar="BASELINE", help="fail (exit 1) if hardened results regress")
    run.add_argument("--write-baseline", metavar="PATH", help="write a baseline that accepts these results")
    run.add_argument(
        "--disable",
        nargs="+",
        default=[],
        metavar="GUARDRAIL",
        choices=Guardrails.names(),
        help="switch guardrails off in the hardened agent: " + ", ".join(Guardrails.names()),
    )
    ask = sub.add_parser("ask", help="send one message to an agent and print what happened")
    ask.add_argument("--agent", choices=sorted(AGENTS), default="weak")
    ask.add_argument("message")
    sub.add_parser("list", help="list attacks with their OWASP categories")
    return p


def cmd_run(args: argparse.Namespace) -> int:
    """Run both agents, print the table, write reports, apply the gate."""
    catalog = load_catalog()
    retriever = Retriever(load_corpus())
    hardened = AGENTS["hardened"].without(*args.disable)
    runs = [
        run_agent("weak", AGENTS["weak"], catalog, retriever=retriever),
        run_agent("hardened", hardened, catalog, retriever=retriever),
    ]
    report = build_report(runs)
    print(console_table(runs))
    if args.json:
        _write(args.json, json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    if args.markdown:
        _write(args.markdown, markdown(runs))
    if args.write_baseline:
        _write(args.write_baseline, json.dumps(gate.make_baseline(report), indent=2) + "\n")
    verdict = None
    problems: list[str] = []
    if args.gate:
        problems = gate.check(report, gate.load_baseline(Path(args.gate)))
        verdict = "FAIL" if problems else "PASS"
        for problem in problems:
            print(f"GATE: {problem}")
    print(result_line(runs, verdict))
    return EXIT_GATE if problems else EXIT_OK


def cmd_ask(args: argparse.Namespace) -> int:
    """One turn, printed as JSON."""
    catalog = load_catalog()
    agent = Agent(ScriptedModel(), Retriever(load_corpus()), catalog.orders, AGENTS[args.agent])
    t = agent.run(args.message)
    print(
        json.dumps(
            {
                "agent": args.agent,
                "retrieved": list(t.retrieved),
                "input_blocked": t.input_blocked,
                "tool_calls_run": [{"tool": c.name, **c.as_dict()} for c in t.executed],
                "tool_calls_blocked": [{"tool": c.name, "reason": r} for c, r in t.blocked],
                "output_filtered": list(t.output_filtered),
                "output": t.output,
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return EXIT_OK


def cmd_list() -> int:
    """Attack ids, suites, OWASP categories and techniques."""
    for a in load_catalog().attacks:
        print(f"{a.id}  {a.suite:20} {','.join(a.owasp):24} {a.technique}")
    covered = {c for a in load_catalog().attacks for c in a.owasp}
    print("not covered: " + ", ".join(f"{c} {t}" for c, t in CATEGORIES.items() if c not in covered))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns the exit code."""
    args = _parser().parse_args(argv)
    try:
        if args.command == "run":
            return cmd_run(args)
        if args.command == "ask":
            return cmd_ask(args)
        return cmd_list()
    except (CatalogError, CorpusError, gate.BaselineError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
