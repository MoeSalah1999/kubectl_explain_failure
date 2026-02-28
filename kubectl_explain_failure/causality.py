from dataclasses import dataclass, field
from typing import Any, Optional


# All roles allowed to be blocking
BLOCKING_ROOT_ROLES = {
    "authorization_root",
    "policy_root",
    "admission_root",
    "identity_root",
    "configuration_root",
    "workload_root",
    "infrastructure_root",
    "execution_root",
    "resource_root",
    "controller_root",
    "container_health_root",
    "scheduling_root",
    "volume_root"
}


@dataclass
class Cause:
    """
    Atomic causal statement.
    """

    code: str
    message: str
    blocking: bool = False
    role: Optional[str] = None

    def __post_init__(self):
        # Ensure blocking causes always have a valid role
        if self.blocking and (self.role is None):
            self.role = "workload_root"  # default safe root role


@dataclass
class CausalChain:
    """
    Ordered chain of causes.
    """

    causes: list[Cause] = field(default_factory=list)

    def _validate_blocking_invariant(self):
        blocking_causes = [c for c in self.causes if c.blocking]

        # Only one blocking cause allowed
        if len(blocking_causes) > 1:
            raise ValueError(
                "CausalChain invariant violation: only one cause may have blocking=True"
            )

        # If there is a blocking cause, it must have a valid root role
        if blocking_causes:
            cause = blocking_causes[0]
            print(f"DEBUG: blocking cause code={cause.code}, role={cause.role!r}")

            if cause.role not in BLOCKING_ROOT_ROLES:
                raise ValueError(
                    f"CausalChain invariant violation: "
                    f"blocking cause role '{cause.role}' "
                    f"is not an approved root role"
                )

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
    Ensures that blocking causes always have a valid root role.
    """
    if "causes" in exp and isinstance(exp["causes"], CausalChain):
        exp["causes"]._validate_blocking_invariant()
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

    # Re-run invariant validation after legacy build
    chain._validate_blocking_invariant()

    return chain