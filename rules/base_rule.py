from typing import Dict, List, Any

class FailureRule:
    name = "BaseRule"
    priority = 100
    category = None           # e.g., "Volume", "Scheduling", "Image"
    severity = "Medium"       # "Low", "Medium", "High"
    dependencies = []         # List of other rule names that must match first

    def matches(self, pod: Dict[str, Any], events: List[Dict[str, Any]], context: Dict[str, Any]) -> bool:
        raise NotImplementedError

    def explain(self, pod: Dict[str, Any], events: List[Dict[str, Any]], context: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError
