from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NodeFragmentationPreventsPreemptionRule(FailureRule):
    """
    Detects scheduling failures where aggregate cluster capacity exists,
    but the Pod's requested resource shape fits on no single node and
    preemption cannot help.

    Real-world interpretation:
    - The cluster has enough total CPU and memory in aggregate
    - The Pod's request cannot fit on any one node
    - Scheduler emits repeated insufficiency + preemption-not-helpful messages
    - This is fragmentation or node-shape mismatch, not simple exhaustion
    """

    name = "NodeFragmentationPreventsPreemption"
    category = "Compound"
    priority = 87
    deterministic = True
    blocks = [
        "InsufficientResources",
        "PodUnschedulable",
        "FailedScheduling",
        "SchedulerPreemptionLoop",
    ]
    phases = ["Pending"]
    requires = {
        "pod": True,
        "objects": ["node"],
        "context": ["timeline"],
    }

    PREEMPTION_MARKERS = (
        "preemption:",
        "preemption is not helpful",
        "no preemption victims found for incoming pod",
        "preempt",
    )

    MEMORY_UNITS = {
        "ki": 1024,
        "mi": 1024**2,
        "gi": 1024**3,
        "ti": 1024**4,
        "k": 1000,
        "m": 1000**2,
        "g": 1000**3,
        "t": 1000**4,
    }

    def _occurrences(self, event) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _parse_cpu_millicores(self, value) -> int:
        text = str(value or "0").strip().lower()
        if not text:
            return 0
        if text.endswith("m"):
            return int(float(text[:-1]))
        return int(float(text) * 1000)

    def _parse_memory_bytes(self, value) -> int:
        text = str(value or "0").strip()
        if not text:
            return 0

        lower = text.lower()
        for suffix, factor in self.MEMORY_UNITS.items():
            if lower.endswith(suffix):
                return int(float(lower[: -len(suffix)]) * factor)

        return int(float(lower))

    def _pod_requests(self, pod) -> dict[str, int]:
        totals = {"cpu": 0, "memory": 0}
        containers = pod.get("spec", {}).get("containers", []) or []

        for container in containers:
            requests = container.get("resources", {}).get("requests", {}) or {}
            if "cpu" in requests:
                totals["cpu"] += self._parse_cpu_millicores(requests.get("cpu"))
            if "memory" in requests:
                totals["memory"] += self._parse_memory_bytes(requests.get("memory"))

        return totals

    def _node_capacity(self, node) -> dict[str, int]:
        allocatable = node.get("status", {}).get("allocatable", {}) or {}
        return {
            "cpu": self._parse_cpu_millicores(allocatable.get("cpu")),
            "memory": self._parse_memory_bytes(allocatable.get("memory")),
        }

    def _aggregate_sufficient_but_no_single_fit(self, pod, nodes: dict) -> bool:
        requests = self._pod_requests(pod)
        if requests["cpu"] <= 0 and requests["memory"] <= 0:
            return False

        total_cpu = 0
        total_memory = 0
        single_fit = False

        for node in nodes.values():
            capacity = self._node_capacity(node)
            total_cpu += capacity["cpu"]
            total_memory += capacity["memory"]

            fits_cpu = requests["cpu"] <= 0 or capacity["cpu"] >= requests["cpu"]
            fits_memory = (
                requests["memory"] <= 0 or capacity["memory"] >= requests["memory"]
            )
            if fits_cpu and fits_memory:
                single_fit = True

        aggregate_cpu_ok = requests["cpu"] <= 0 or total_cpu >= requests["cpu"]
        aggregate_memory_ok = (
            requests["memory"] <= 0 or total_memory >= requests["memory"]
        )

        return aggregate_cpu_ok and aggregate_memory_ok and not single_fit

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        nodes = context.get("objects", {}).get("node", {})
        if not timeline or not nodes:
            return False
        if not self._aggregate_sufficient_but_no_single_fit(pod, nodes):
            return False

        recent = timeline.events_within_window(15, reason="FailedScheduling")
        if not recent:
            return False

        insufficient_signals = 0
        preemption_signals = 0
        multi_node_pattern = 0
        total_failures = 0
        repeated_signal = False

        for event in recent:
            message = str(event.get("message", "")).lower()
            occurrences = self._occurrences(event)
            total_failures += occurrences
            if occurrences >= 2:
                repeated_signal = True

            if "insufficient" in message:
                insufficient_signals += occurrences
            if any(marker in message for marker in self.PREEMPTION_MARKERS):
                preemption_signals += occurrences
            if "nodes are available" in message or "0/" in message:
                multi_node_pattern += occurrences

        if insufficient_signals < 3:
            return False
        if preemption_signals < 2:
            return False
        if total_failures < 3:
            return False
        if multi_node_pattern < 3:
            return False

        duration = timeline.duration_between(
            lambda event: event.get("reason") == "FailedScheduling"
        )
        if duration < 60 and not repeated_signal:
            return False

        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        nodes = context.get("objects", {}).get("node", {})
        requests = self._pod_requests(pod)

        dominant_msg = None
        if timeline:
            messages = [
                str(event.get("message", ""))
                for event in timeline.events_within_window(
                    15, reason="FailedScheduling"
                )
                if event.get("message")
            ]
            if messages:
                dominant_msg = max(set(messages), key=messages.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="CLUSTER_RESOURCE_FRAGMENTATION",
                    message="Cluster resources are fragmented across nodes",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="INSUFFICIENT_CONTIGUOUS_RESOURCES",
                    message="No single node has sufficient contiguous resources for the Pod",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="PREEMPTION_INEFFECTIVE",
                    message="Preemption cannot consolidate fragmented resources",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="SCHEDULER_BINPACKING_FAILURE",
                    message="Scheduler cannot place Pod due to per-node bin-packing constraints",
                    role="control_loop",
                ),
            ]
        )

        return {
            "root_cause": "Pod cannot be scheduled due to node resource fragmentation preventing effective preemption",
            "confidence": 0.94,
            "causes": chain,
            "evidence": [
                "Repeated FailedScheduling events within short time window",
                f"Aggregate cluster capacity exceeds pod request, but no node fits the full request (cpu={requests['cpu']}m, memory={requests['memory']} bytes)",
                "Scheduler reports insufficient resources across multiple nodes",
                "Preemption attempts observed but ineffective",
                "Sustained scheduling failure duration (>60s)",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "Cluster resources are fragmented across nodes",
                "Pod resource requests are too large for any single node shape",
                "Existing workload placement leaves unusable resource gaps",
                "Preemption cannot free a node with the required combined CPU and memory",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl describe nodes",
                "kubectl top nodes",
                "Check per-node allocatable versus requested resources",
                "Evaluate pod CPU and memory requests",
                "Inspect current pod distribution across nodes",
                "Consider autoscaling or larger node shapes",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod repeatedly failed scheduling due to fragmented node capacity"
                ],
                **{
                    f"node:{node_name}": [
                        "Node cannot satisfy the pod's full resource shape on its own"
                    ]
                    for node_name in nodes
                },
            },
        }
