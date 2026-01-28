from typing import Dict, List, Any

class FailureRule:
    name: str
    priority: int = 100  # default

    def matches(self, pod: Dict[str, Any], events: List[Dict[str, Any]], context: Dict[str, Any]) -> bool:
        raise NotImplementedError

    def explain(self, pod: Dict[str, Any], events: List[Dict[str, Any]], context: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError
