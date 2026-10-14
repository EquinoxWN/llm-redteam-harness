# ADR 0002: A deterministic stand-in model for M1, behind a pluggable model interface

- **Status:** Accepted

## Context

The harness needs a target agent to attack. Its first job in CI is to prove that the harness
itself works: that every detector fires when it should, that the ASR arithmetic is right, and that
the regression gate fails when a defence is removed. That proof needs outcomes that are exactly the
same on every run and every machine.

The owner's rules exclude external LLM APIs and API keys. A small local open model is allowed but
optional. On this machine about 2.5 GB of RAM is free while other builds run in parallel, and CI
would have to download the weights for every run. Sampling, quantisation and library versions make
a local model's outputs differ between machines, so a gate built on them would need tolerances,
and a broken detector could hide inside those tolerances.

## Decision

The agent talks to its model through one method, `ChatModel.generate(messages, tools)`. For M1 the
model is `ScriptedModel`, a rule-based reader of its context that copies well-known LLM failure
modes on purpose: it treats text in retrieved pages and tool results as instructions unless it is
spotlighted, understands obfuscated and non-English override phrases, keeps its confidentiality
rule only until an override phrase appears, repeats its prompt when asked, follows a poisoned guide
when the user delegates to it, and requests any tool it is asked for. Its behaviour is specified in
`model.py` and pinned by 19 unit tests.

No local model is run in M1, so no model files are downloaded, and nothing has to be deleted after
the runs. When M2 adds one, it goes behind the same interface, with its id, revision and seed in the
results, and its files deleted after the run (owner's process rule).

## Consequences

- Every result is reproducible: three runs gave byte-identical reports, and the tests pin the
  exact set of successful attacks for both agents.
- CI needs no GPU, no download and no secrets; a full run of both agents takes about 1.5 s.
- The numbers describe this sample agent, not any language model. Every report, the README and the
  results say so. The stand-in's weaknesses are chosen by its author, which is exactly why M2 puts
  a real local model behind the same interface and compares.
- Building the stand-in found two defects that would also hit a real agent loop: tool confirmations
  phrased like requests ("Email to X ...") were read back as new instructions and repeated the call
  on every step, and the page title won answer selection. Both are fixed and covered by regression
  tests (`test_tool_results_never_read_as_new_instructions`).
