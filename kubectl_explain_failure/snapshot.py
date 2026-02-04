from typing import Any


class ClusterSnapshot:
    """
    Normalized view of all Kubernetes objects relevant to diagnosis.
    """

    def __init__(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ):
        self.pod = pod
        self.events = events

        self.node: dict[str, Any] | None = context.get("node")
        self.pvcs: list[dict[str, Any]] = context.get("pvcs", [])
        self.pvc: dict[str, Any] | None = context.get("pvc")
        self.services: list[dict[str, Any]] = context.get("svc", [])
        self.endpoints: list[dict[str, Any]] = context.get("ep", [])
        self.statefulsets: list[dict[str, Any]] = context.get("sts", [])
        self.daemonsets: list[dict[str, Any]] = context.get("ds", [])

    @property
    def pod_phase(self) -> str:
        return self.pod.get("status", {}).get("phase", "Unknown")

    @property
    def pod_name(self) -> str:
        return self.pod.get("metadata", {}).get("name", "<unknown>")
