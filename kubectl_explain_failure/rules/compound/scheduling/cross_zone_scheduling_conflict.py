from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CrossZoneSchedulingConflictRule(FailureRule):
    """
    Detects Pods that remain Pending because placement is constrained to a
    topology zone that lacks feasible capacity while other zones remain
    available but filtered out.

    Real-world interpretation:
    - The cluster spans multiple zones
    - The Pod has hard zone-aware placement constraints
    - Scheduler events show both filtered nodes and capacity pressure
    - Capacity may exist elsewhere, but not in the permitted zone
    """

    name = "CrossZoneSchedulingConflict"
    category = "Compound"
    priority = 82
    deterministic = True
    blocks = [
        "PodUnschedulable",
        "FailedScheduling",
        "InsufficientResources",
        "AffinityUnsatisfiable",
        "NodeAffinityRequiredMismatch",
        "PodTopologySpreadLabelMismatch",
        "TopologySpreadUnsatisfiable",
        "TopologyKeyMissing",
    ]
    phases = ["Pending"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["node"],
    }

    ZONE_KEYS = (
        "topology.kubernetes.io/zone",
        "failure-domain.beta.kubernetes.io/zone",
    )

    EXCLUSION_MARKERS = (
        "missing required label",
        "volume node affinity conflict",
        "already attached",
        "multi-attach",
    )

    def _occurrences(self, event) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _cluster_zones(self, nodes: dict) -> dict[str, list[str]]:
        zones: dict[str, list[str]] = {}
        for node_name, node in nodes.items():
            labels = node.get("metadata", {}).get("labels", {}) or {}
            zone = None
            for key in self.ZONE_KEYS:
                if labels.get(key):
                    zone = labels[key]
                    break
            if zone:
                zones.setdefault(zone, []).append(node_name)
        return zones

    def _required_zones_from_node_affinity(self, pod: dict) -> set[str]:
        affinity = pod.get("spec", {}).get("affinity", {}) or {}
        node_affinity = affinity.get("nodeAffinity", {}) or {}
        required = node_affinity.get(
            "requiredDuringSchedulingIgnoredDuringExecution", {}
        )
        zones: set[str] = set()

        for term in required.get("nodeSelectorTerms", []) or []:
            for expression in term.get("matchExpressions", []) or []:
                if expression.get("key") not in self.ZONE_KEYS:
                    continue
                if expression.get("operator") == "In":
                    zones.update(expression.get("values", []) or [])

        return zones

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        nodes = context.get("objects", {}).get("node", {})
        if not timeline or not nodes:
            return False

        cluster_zones = self._cluster_zones(nodes)
        if len(cluster_zones) < 2:
            return False

        required_zones = self._required_zones_from_node_affinity(pod)
        if not required_zones:
            return False
        if required_zones and not any(zone in cluster_zones for zone in required_zones):
            return False
        if required_zones and not any(
            zone not in required_zones for zone in cluster_zones
        ):
            return False

        recent_failures = timeline.events_within_window(15, reason="FailedScheduling")
        if not recent_failures:
            return False

        topology_hits = 0
        contention_hits = 0
        total_failures = 0
        repeated_signal = False

        for event in recent_failures:
            message = str(event.get("message", "")).lower()
            occurrences = self._occurrences(event)
            total_failures += occurrences
            if occurrences >= 2:
                repeated_signal = True

            if any(marker in message for marker in self.EXCLUSION_MARKERS):
                return False

            if (
                "node affinity" in message
                or any(key in message for key in self.ZONE_KEYS)
                or "zone" in message
            ):
                topology_hits += occurrences

            if (
                "insufficient" in message
                or "didn't match pod's node affinity/selector" in message
            ):
                contention_hits += occurrences

        if topology_hits < 2:
            return False
        if contention_hits < 2:
            return False
        if total_failures < 3:
            return False

        duration = timeline.duration_between(
            lambda event: event.get("reason") == "FailedScheduling"
        )
        if duration < 45 and not repeated_signal:
            return False

        if timeline.count(reason="Scheduled") > 0:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        nodes = context.get("objects", {}).get("node", {})
        cluster_zones = self._cluster_zones(nodes)
        timeline = context.get("timeline")

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
                    code="ZONE_AWARE_PLACEMENT_CONSTRAINT",
                    message="Pod declares hard zone-aware placement constraints",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="TARGET_ZONE_INSUFFICIENT_CAPACITY",
                    message="Eligible nodes in the required zone do not provide a feasible placement",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="CROSS_ZONE_FILTER_CONFLICT",
                    message="Nodes in other zones are filtered out even though the cluster spans multiple zones",
                    role="scheduling_decision",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains Pending because zone-aware constraints conflict with available capacity",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Pod cannot be scheduled because required zone placement conflicts with available capacity",
            "confidence": 0.91,
            "causes": chain,
            "evidence": [
                f"Cluster spans multiple zones: {', '.join(sorted(cluster_zones))}",
                "Pod defines zone-aware placement constraints",
                "Scheduler messages indicate both zone filtering and capacity pressure",
                "Sustained scheduling failure duration (>45s)",
                "No successful scheduling observed",
                *(
                    ["Dominant scheduler message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "Node affinity or topology rules restrict the pod to a zone without enough free capacity",
                "Capacity exists in other zones, but hard placement constraints exclude them",
                "Zone-aware placement policy is stricter than current cross-zone resource distribution",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get nodes --show-labels",
                "Check topology.kubernetes.io/zone labels on nodes",
                "Review pod affinity, anti-affinity, and topologySpreadConstraints",
                "Compare resource availability across zones",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod repeatedly failed scheduling due to zone-aware placement constraints"
                ]
            },
        }
