from typing import Any, Literal


class FailureRule:
    """
    Base class for all diagnostic rules.
    """

    # ---- Metadata (mandatory) ----
    name: str = "BaseRule"
    category: str = "Generic"
    severity: Literal["Low", "Medium", "High"] = "Medium"
    priority: int = 100

    # ---- Optional execution hints ----
    phases: list[str] = []  # e.g. ["Pending", "Running"]
    container_states: list[str] = []  # e.g. ["waiting", "terminated"]
    dependencies: list[str] = []  # names of other rules

    # ---- Blocking / suppression semantics ----
    blocks: list[str] = []  # names of rules this rule suppresses

    # ---- Contract requirements ----
    requires = {
        "pod": True,
        "events": True,
        "context": [],  # e.g. ["node", "pvcs"]
        "objects": [],
        "optional_objects": [],
    }

    def matches(
        self, pod: dict[str, Any], events: list[dict[str, Any]], context: dict[str, Any]
    ) -> bool:
        raise NotImplementedError

    def explain(
        self, pod: dict[str, Any], events: list[dict[str, Any]], context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Must return:
        {
          "root_cause": str,
          "confidence": float (0..1),
          "evidence": [str],
          "likely_causes": [str],
          "suggested_checks": [str],
          "object_evidence": {
              "<object-id>": [str]
          }
        }
        }
        """
        raise NotImplementedError
