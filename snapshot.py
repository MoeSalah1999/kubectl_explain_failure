from typing import Dict, Any, List, Optional

class ClusterSnapshot:
    """
    Normalized view of all Kubernetes objects relevant to diagnosis.
    """

    def __init__(
        self,
        pod: Dict[str, Any],
        events: List[Dict[str, Any]],
        context: Dict[str, Any],
    ):
        self.pod = pod
        self.events = events

        self.node: Optional[Dict[str, Any]] = context.get("node")
        self.pvcs: List[Dict[str, Any]] = context.get("pvcs", [])
        self.pvc: Optional[Dict[str, Any]] = context.get("pvc")
        self.services: List[Dict[str, Any]] = context.get("svc", [])
        self.endpoints: List[Dict[str, Any]] = context.get("ep", [])
        self.statefulsets: List[Dict[str, Any]] = context.get("sts", [])
        self.daemonsets: List[Dict[str, Any]] = context.get("ds", [])

    @property
    def pod_phase(self) -> str:
        return self.pod.get("status", {}).get("phase", "Unknown")

    @property
    def pod_name(self) -> str:
        return self.pod.get("metadata", {}).get("name", "<unknown>")
