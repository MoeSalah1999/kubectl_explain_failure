from typing import Dict, List, Any, Literal

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
    phases: List[str] = []            # e.g. ["Pending", "Running"]
    container_states: List[str] = []  # e.g. ["waiting", "terminated"]
    dependencies: List[str] = []      # names of other rules

    # ---- Contract requirements ----
    requires = {
        "pod": True,
        "events": True,
        "context": [],   # e.g. ["node", "pvcs"]
    }

    def matches(
        self,
        pod: Dict[str, Any],
        events: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> bool:
        raise NotImplementedError

    def explain(
        self,
        pod: Dict[str, Any],
        events: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Must return:
        {
          "root_cause": str,
          "confidence": float (0..1),
          "evidence": [str],
          "likely_causes": [str],
          "suggested_checks": [str]
        }
        """
        raise NotImplementedError

