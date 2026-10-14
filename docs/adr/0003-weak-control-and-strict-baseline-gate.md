# ADR 0003: Gate on a strict baseline, with the weak agent as a control

- **Status:** Accepted

## Context

CI must fail when the hardened agent gets worse. The simplest gate is a single threshold, for
example "overall ASR at most 15%". It has two blind spots:

1. **Swaps.** A change can block one attack and let a different, more serious one through. The
   overall rate stays the same and the threshold passes, while a fake tool that was never reachable
   now runs.
2. **Silent breakage.** If a detector stops firing (a renamed tool, a changed marker, a fixture
   typo), the hardened ASR drops, which looks like an improvement.

## Decision

The gate compares the hardened agent with a committed baseline (`baselines/hardened.json`) and
fails on any of:

- overall ASR, ASR of any suite or ASR of any OWASP category above the baseline;
- any attack that succeeds but is not in the baseline's list of known residuals (catches swaps);
- a suite or category the baseline does not know (new fixtures need a reviewed baseline update);
- utility on benign tasks below the baseline (catches over-blocking);
- the **weak** agent's ASR below its floor (catches silent breakage: the attacks must keep landing
  on the undefended agent).

The baseline is written only by `make baseline` (`lrh run --write-baseline`), so accepting a worse
result is a visible change in a pull request. Improvements always pass.

## Consequences

- The gate is strict: any new residual, even one that leaves the rate unchanged, fails CI
  (`test_gate_fails_on_a_swapped_success_with_the_same_rate`). Removing `tool_policy` and
  `least_privilege` fails it with eight named attacks; removing `tool_policy` alone fails it with
  six.
- Adding an attack to a fixture changes rates and requires a baseline update in the same pull
  request. That is deliberate friction: a new attack is a new measurement.
- The exact-rate baseline suits a deterministic target. A non-deterministic model (M2) will need a
  tolerance or repeated runs per attack; the baseline schema has a version field for that change.
