from dataclasses import dataclass, field
from typing import Any


@dataclass
class Cause:
    """
    Atomic causal statement.
    """

    code: str
    message: str
    blocking: bool = False
    role: str | None = None


@dataclass
class CausalChain:
    """
    Ordered chain of causes.
    """

    causes: list[Cause] = field(default_factory=list)

    def root(self) -> Cause | None:
        return self.causes[0] if self.causes else None

    def is_blocking(self) -> bool:
        return any(c.blocking for c in self.causes)


@dataclass
class Resolution:
    """
    Explicit conflict resolution result.
    """

    winner: str
    suppressed: list[str]
    reason: str


def build_chain(exp: dict[str, Any]) -> CausalChain:
    """
    Build a causal chain from a rule explanation.
    Supports both legacy flat explanations and explicit causal chains.
    """
    if "causes" in exp and isinstance(exp["causes"], CausalChain):
        return exp["causes"]

    chain = CausalChain()

    root = exp.get("root_cause")
    if root:
        chain.causes.append(
            Cause(
                code=exp.get("code", root.upper().replace(" ", "_")),
                message=root,
                blocking=exp.get("blocking", False),
                role=exp.get("role"),
            )
        )

    for cause in exp.get("likely_causes", []):
        chain.causes.append(
            Cause(
                code=cause.upper().replace(" ", "_"),
                message=cause,
                blocking=False,
                role="contributing",
            )
        )

    return chain
