from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class TopologyKeyMissingRule(FailureRule):
    """
    Detects scheduling failures where topologySpreadConstraints reference
    a topologyKey that is not present on cluster nodes.

    Signals:
    - Pod.spec.topologySpreadConstraints present
    - FailedScheduling events
    - Nodes lack required topologyKey labels

    Interpretation:
    Scheduler cannot evaluate topology spread because nodes do not
    have the required topologyKey label.

    This handles REAL scheduler behavior where error messages are vague:
    e.g. "node(s) didn't match pod's topology spread constraints"

    Scope:
    - Scheduler-level failure
    - Deterministic (event + object graph)
    """

    name = "TopologyKeyMissing"
    category = "Scheduling"
    priority = 22
    deterministic = True
    blocks = []
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["node"],  # IMPORTANT: required for correctness
    }

    phases = ["Pending"]

    def _nodes_missing_key(self, nodes: dict, topology_keys: list[str]) -> bool:
        """
        Returns True if NONE of the nodes have the required topology keys.
        """
        if not nodes or not topology_keys:
            return False

        for node in nodes.values():
            labels = node.get("metadata", {}).get("labels", {}) or {}

            # If any node has ANY required key → not missing
            for key in topology_keys:
                if key in labels:
                    return False

        return True  # all nodes missing keys

    def matches(self, pod, events, context) -> bool:
        spec = pod.get("spec", {})
        constraints = spec.get("topologySpreadConstraints")

        if not constraints:
            return False

        timeline = context.get("timeline")
        if not timeline:
            return False

        # Extract topology keys from pod spec
        topology_keys = [
            c.get("topologyKey") for c in constraints if c.get("topologyKey")
        ]

        if not topology_keys:
            return False

        # Check scheduler failures exist
        failed = [
            e for e in timeline.raw_events if e.get("reason") == "FailedScheduling"
        ]

        if not failed:
            return False

        # Access node objects (object graph)
        nodes = context.get("objects", {}).get("node", {})

        # Core correctness check (NOT string matching)
        if self._nodes_missing_key(nodes, topology_keys):
            return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "unknown")

        spec = pod.get("spec", {})
        constraints = spec.get("topologySpreadConstraints", [])

        topology_keys = [
            c.get("topologyKey") for c in constraints if c.get("topologyKey")
        ]

        nodes = context.get("objects", {}).get("node", {})
        node_count = len(nodes)

        chain = CausalChain(
            causes=[
                Cause(
                    code="TOPOLOGY_SPREAD_CONSTRAINT_DEFINED",
                    message="Pod defines topology spread constraints",
                    role="scheduling_context",
                ),
                Cause(
                    code="TOPOLOGY_KEY_MISSING_ON_NODES",
                    message="Required topology key is not present on any node",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_UNSCHEDULABLE_TOPOLOGY_KEY",
                    message="Scheduler cannot evaluate topology spread constraints",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            "Pod.spec.topologySpreadConstraints present",
            f"{node_count} nodes evaluated for topology labels",
            "No nodes contain required topologyKey labels",
        ]

        if topology_keys:
            evidence.append(f"Topology keys: {', '.join(topology_keys)}")

        return {
            "rule": self.name,
            "root_cause": "Topology key missing on nodes prevents scheduling",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Topology spread constraints reference missing node labels"
                ]
            },
            "likely_causes": [
                "Cluster nodes are missing required topology labels",
                "Incorrect topologyKey configured in Pod spec",
                "Node labeling not applied (e.g., missing zone/region labels)",
            ],
            "suggested_checks": [
                "kubectl get nodes --show-labels",
                f"kubectl describe pod {pod_name}",
                "Verify topologySpreadConstraints topologyKey values",
                "Ensure nodes are labeled with required topology keys",
            ],
        }
