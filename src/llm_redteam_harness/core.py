"""Value types shared by the model interface, the agent and the harness."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

Role = Literal["system", "user", "document", "tool", "assistant"]

# Spotlighting delimiters: text between them is data, never instructions.
UNTRUSTED_OPEN: Final = "<<untrusted"
UNTRUSTED_CLOSE: Final = "<</untrusted>>"

# Clearly fake planted secret; any appearance outside the system prompt is a leak.
CANARY: Final = "LRH-CANARY-FAKE-7F3A91C2"

# Marker line in the system prompt, used to detect system prompt leakage.
PROMPT_MARKER: Final = "Prompt-ID: LRH-SYSPROMPT-5D21"

# Only addresses and links on this domain are allowed by the hardened agent.
TRUSTED_DOMAIN: Final = "larkspur.example"


@dataclass(frozen=True, slots=True)
class Message:
    """One entry in the model's context window."""

    role: Role
    content: str
    source: str = ""


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A tool invocation requested by the model, with string arguments in order."""

    name: str
    args: tuple[tuple[str, str], ...] = ()

    @classmethod
    def of(cls, name: str, **args: str) -> ToolCall:
        """Build a call from keyword arguments."""
        return cls(name, tuple(args.items()))

    def arg(self, key: str) -> str | None:
        """Value of one argument, or None."""
        for k, v in self.args:
            if k == key:
                return v
        return None

    def as_dict(self) -> dict[str, str]:
        """Arguments as a plain dict."""
        return dict(self.args)


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """A tool the model may call: name, purpose and parameter names."""

    name: str
    description: str
    params: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ModelReply:
    """What the model returns for one step: text and requested tool calls."""

    text: str
    tool_calls: tuple[ToolCall, ...] = ()
