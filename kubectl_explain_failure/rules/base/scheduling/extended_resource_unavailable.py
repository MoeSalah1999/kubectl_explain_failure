from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import build_timeline


class ExtendedResourceUnavailableRule(FailureRule):
    """
    Detects scheduling failures caused by unavailable extended resources.

    Signals:
    - Pod container requests an extended resource (e.g. nvidia.com/gpu)
    - Scheduler emits FailedScheduling events referencing that resource

    Interpretation:
    The Pod requests a vendor-specific extended resource that no node
    advertises in allocatable capacity. The scheduler therefore cannot
    place the workload.

    Scope:
    - Scheduler-level resource constraint
    - Deterministic when extended resource requests and scheduling
      failures clearly reference the resource.
    """

    name = "ExtendedResourceUnavailable"
    category = "Scheduling"
    priority = 18
    deterministic = True

    blocks = ["InsufficientResources"]

    requires = {
        "pod": True,
        "objects": ["node"],
    }

    def _collect_extended_requests(self, pod):
        """
        Extract extended resource requests from pod containers.

        Extended resources follow the pattern:
            vendor-domain/resource
        Example:
            nvidia.com/gpu
        """
        spec = pod.get("spec", {})
        containers = spec.get("containers", [])

        extended = {}

        for c in containers:
            resources = c.get("resources", {})
            requests = resources.get("requests", {}) or {}

            for rname, value in requests.items():
                if "/" in rname:
                    extended[rname] = value

        return extended

    def matches(self, pod, events, context) -> bool:
        extended = self._collect_extended_requests(pod)

        if not extended:
            return False

        nodes = context.get("objects", {}).get("node", {})
        if not nodes:
            return False

        timeline = build_timeline(events)

        sched_events = timeline.events_within_window(
            15,
            reason="FailedScheduling",
        )

        if not sched_events:
            return False

        # Check scheduler messages referencing the resource
        for e in sched_events:
            msg = (e.get("message") or "").lower()

            for resource in extended:
                if resource.lower() in msg:
                    return True

        # Deterministic fallback:
        # no node advertises requested extended resource
        for resource in extended:
            resource_present = False

            for node in nodes.values():
                alloc = node.get("status", {}).get("allocatable", {})
                if resource in alloc:
                    resource_present = True
                    break

            if not resource_present:
                return True

        return False

    def explain(self, pod, events, context):
        extended = self._collect_extended_requests(pod)

        nodes = context.get("objects", {}).get("node", {})

        timeline = build_timeline(events)

        sched_events = timeline.events_within_window(
            15,
            reason="FailedScheduling",
        )

        evidence_msgs = []

        for e in sched_events:
            msg = e.get("message")
            if not msg:
                continue

            lower = msg.lower()

            for r in extended:
                if r.lower() in lower:
                    evidence_msgs.append(msg)

        resource_list = ", ".join(extended.keys())

        pod_name = pod.get("metadata", {}).get("name", "unknown")

        chain = CausalChain(
            causes=[
                Cause(
                    code="EXTENDED_RESOURCE_REQUESTED",
                    message="Pod requests vendor-specific extended resource",
                    role="scheduling_context",
                ),
                Cause(
                    code="EXTENDED_RESOURCE_NOT_AVAILABLE",
                    message="Requested extended resource not present in node allocatable capacity",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_PENDING_RESOURCE_UNAVAILABLE",
                    message="Scheduler cannot place Pod due to unavailable extended resource",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod requests an extended resource that no node provides",
            "confidence": 0.96,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"Extended resource requests detected: {resource_list}",
                f"{len(sched_events)} FailedScheduling events observed",
                *evidence_msgs[:2],
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    f"Extended resource requests: {resource_list}",
                ]
            },
            "likely_causes": [
                "GPU or accelerator nodes are not present in the cluster",
                "Device plugin for the resource is not installed",
                "Nodes advertising the resource are currently unavailable",
                "Incorrect resource name used in pod spec",
            ],
            "suggested_checks": [
                "kubectl get nodes -o json | jq '.items[].status.allocatable'",
                f"kubectl describe pod {pod_name}",
                "Verify device plugin deployment for the resource",
                "Check node labels and GPU node availability",
            ],
        }