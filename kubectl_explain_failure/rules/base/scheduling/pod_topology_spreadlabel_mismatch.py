from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PodTopologySpreadLabelMismatchRule(FailureRule):
    """
    Detects scheduling failures where topology spread constraints reference
    topology keys that exist on some nodes, but candidate nodes are
    inconsistently labeled and therefore cannot satisfy the spread policy.

    Real-world interpretation:
    - The Pod defines topologySpreadConstraints
    - Scheduler reports topology spread constraint failures
    - Some nodes carry the required topology label, but others do not
    - This is more specific than a cluster-wide missing topology key

    Scope:
    - Scheduler constraint failure
    - Deterministic (pod spec + node labels + scheduler event)
    """

    name = "PodTopologySpreadLabelMismatch"
    category = "Scheduling"
    priority = 23
    deterministic = True
    blocks = ["FailedScheduling"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["node"],
    }
    phases = ["Pending"]

    TOPOLOGY_EVENT_MARKERS = (
        "topology spread",
        "topology spread constraints",
        "didn't match pod's topology spread constraints",
        "didn't match pod topology spread constraints",
    )

    MISMATCH_MARKERS = (
        "missing required label",
        "missing label",
        "didn't match pod's topology spread constraints",
        "didn't match pod topology spread constraints",
    )

    EXCLUSION_MARKERS = (
        "maxskew",
        "skew",
        "unsatisfiable",
        "cannot satisfy topology spread",
    )

    def _topology_keys(self, pod) -> list[str]:
        constraints = pod.get("spec", {}).get("topologySpreadConstraints", [])
        return [c.get("topologyKey") for c in constraints if c.get("topologyKey")]

    def _nodes_missing_keys(self, nodes: dict, topology_keys: list[str]) -> list[str]:
        missing = []
        for node_name, node in nodes.items():
            labels = node.get("metadata", {}).get("labels", {}) or {}
            if any(key not in labels for key in topology_keys):
                missing.append(node_name)
        return missing

    def matches(self, pod: dict, events: list[dict], context: dict) -> bool:
        timeline = context.get("timeline")
        nodes = context.get("objects", {}).get("node", {})
        topology_keys = self._topology_keys(pod)

        if not timeline or not nodes or not topology_keys:
            return False

        missing_nodes = self._nodes_missing_keys(nodes, topology_keys)
        if not missing_nodes:
            return False

        # If every node is missing the topology key, TopologyKeyMissing is the
        # more accurate root cause.
        if len(missing_nodes) == len(nodes):
            return False

        for event in timeline.raw_events:
            if event.get("reason") != "FailedScheduling":
                continue

            message = str(event.get("message", "")).lower()
            if any(marker in message for marker in self.EXCLUSION_MARKERS):
                continue
            if not any(marker in message for marker in self.TOPOLOGY_EVENT_MARKERS):
                continue
            if any(marker in message for marker in self.MISMATCH_MARKERS):
                return True

        return False

    def explain(self, pod: dict, events: list[dict], context: dict) -> dict:
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        nodes = context.get("objects", {}).get("node", {})
        topology_keys = self._topology_keys(pod)
        missing_nodes = self._nodes_missing_keys(nodes, topology_keys)

        chain = CausalChain(
            causes=[
                Cause(
                    code="TOPOLOGY_SPREAD_CONSTRAINT_DEFINED",
                    message="Pod defines topology spread constraints",
                    role="scheduling_context",
                ),
                Cause(
                    code="NODE_TOPOLOGY_LABEL_MISMATCH",
                    message="Candidate nodes are inconsistently labeled for the required topology key",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="TOPOLOGY_SPREAD_PLACEMENT_REJECTED",
                    message="Scheduler cannot satisfy topology spread constraints on available nodes",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="POD_UNSCHEDULABLE_TOPOLOGY",
                    message="Pod remains Pending due to topology spread label mismatch",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            "FailedScheduling event references topology spread constraint mismatch",
            f"Nodes missing required topology labels: {', '.join(missing_nodes)}",
        ]
        if topology_keys:
            evidence.append(f"Topology keys: {', '.join(topology_keys)}")

        object_evidence = {
            f"pod:{pod_name}": [
                "Topology spread constraints cannot be satisfied by current node labels"
            ]
        }
        for node_name in missing_nodes:
            object_evidence[f"node:{node_name}"] = [
                "Missing required topology label for pod topology spread"
            ]

        return {
            "root_cause": "Topology spread node label mismatch prevents scheduling",
            "confidence": 0.94,
            "causes": chain,
            "evidence": evidence,
            "likely_causes": [
                "Some nodes are missing the topology labels referenced by topologySpreadConstraints",
                "Node labeling is inconsistent across the cluster",
                "Topology spread policy expects zones or hostnames that are not uniformly present",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get nodes --show-labels",
                "Verify topologySpreadConstraints topologyKey values",
                "Ensure all candidate nodes carry consistent topology labels",
            ],
            "blocking": True,
            "object_evidence": object_evidence,
        }
