from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NodeAffinityRequiredMismatchRule(FailureRule):
    """
    Detects FailedScheduling caused by required nodeAffinity constraints
    that match no available node.

    Real-world interpretation:
    - The Pod uses requiredDuringSchedulingIgnoredDuringExecution
    - The scheduler reports node affinity or selector mismatch
    - Evaluating current node labels shows zero nodes satisfy the hard terms
    - This is more specific than the generic affinity-unsatisfiable fallback
    """

    name = "NodeAffinityRequiredMismatch"
    category = "Scheduling"
    priority = 28
    deterministic = True
    blocks = ["AffinityUnsatisfiable", "FailedScheduling", "PendingUnschedulable"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["node"],
    }
    phases = ["Pending"]

    NODE_AFFINITY_MARKERS = (
        "didn't match pod's node affinity/selector",
        "didn't match pod's node affinity",
        "didn't match pod node affinity",
        "node affinity",
    )

    def _required_node_affinity(self, pod: dict) -> dict | None:
        affinity = pod.get("spec", {}).get("affinity", {}) or {}
        node_affinity = affinity.get("nodeAffinity", {}) or {}
        return node_affinity.get("requiredDuringSchedulingIgnoredDuringExecution")

    def _expression_matches(self, labels: dict, expression: dict) -> bool:
        key = expression.get("key")
        operator = expression.get("operator")
        values = expression.get("values", []) or []
        actual = labels.get(key)

        if operator == "In":
            return actual in values
        if operator == "NotIn":
            return actual is not None and actual not in values
        if operator == "Exists":
            return key in labels
        if operator == "DoesNotExist":
            return key not in labels
        if operator == "Gt":
            try:
                return actual is not None and int(actual) > int(values[0])
            except Exception:
                return False
        if operator == "Lt":
            try:
                return actual is not None and int(actual) < int(values[0])
            except Exception:
                return False
        return False

    def _field_matches(self, node: dict, requirement: dict) -> bool:
        key = requirement.get("key")
        operator = requirement.get("operator")
        values = requirement.get("values", []) or []

        if key == "metadata.name":
            actual = node.get("metadata", {}).get("name")
        else:
            return False

        if operator == "In":
            return actual in values
        if operator == "NotIn":
            return actual is not None and actual not in values
        if operator == "Exists":
            return actual is not None
        if operator == "DoesNotExist":
            return actual is None
        return False

    def _term_matches(self, node: dict, term: dict) -> bool:
        labels = node.get("metadata", {}).get("labels", {}) or {}

        for expression in term.get("matchExpressions", []) or []:
            if not self._expression_matches(labels, expression):
                return False

        for field_requirement in term.get("matchFields", []) or []:
            if not self._field_matches(node, field_requirement):
                return False

        return True

    def _matching_nodes(self, pod: dict, nodes: dict) -> list[str]:
        required = self._required_node_affinity(pod) or {}
        terms = required.get("nodeSelectorTerms", []) or []
        if not terms:
            return []

        matches = []
        for node_name, node in nodes.items():
            if any(self._term_matches(node, term) for term in terms):
                matches.append(node_name)
        return matches

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        nodes = context.get("objects", {}).get("node", {})
        if not timeline or not nodes:
            return False
        if not self._required_node_affinity(pod):
            return False
        if self._matching_nodes(pod, nodes):
            return False

        recent = timeline.events_within_window(15, reason="FailedScheduling")
        if not recent:
            return False

        for event in recent:
            message = str(event.get("message", "")).lower()
            if any(marker in message for marker in self.NODE_AFFINITY_MARKERS):
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        nodes = context.get("objects", {}).get("node", {})
        required = self._required_node_affinity(pod) or {}
        terms = required.get("nodeSelectorTerms", []) or []
        node_names = sorted(nodes.keys())

        chain = CausalChain(
            causes=[
                Cause(
                    code="NODE_AFFINITY_REQUIRED",
                    message="Pod declares required node affinity terms",
                    role="workload_context",
                ),
                Cause(
                    code="NODE_AFFINITY_REQUIRED_MISMATCH",
                    message="No available node satisfies the Pod's required node affinity",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="SCHEDULER_REJECTION",
                    message="Scheduler rejects all nodes because node affinity requirements are unsatisfied",
                    role="scheduling_intermediate",
                ),
                Cause(
                    code="POD_PENDING",
                    message="Pod remains Pending because required node affinity cannot be satisfied",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Required node affinity does not match any available node",
            "confidence": 0.96,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Pod defines required nodeAffinity terms",
                f"No nodes satisfy the required node affinity across {len(node_names)} evaluated nodes",
                f"Node selector terms evaluated: {len(terms)}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Required node affinity terms do not match any current node labels"
                ],
                **{
                    f"node:{name}": [
                        "Node labels do not satisfy the Pod's required node affinity"
                    ]
                    for name in node_names
                },
            },
            "likely_causes": [
                "Required node affinity targets labels that are absent from all nodes",
                "Cluster node labels drifted from the Pod's hard placement requirements",
                "The Pod should use preferred affinity instead of required affinity",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get nodes --show-labels",
                "Check pod.spec.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution",
                "Add matching node labels or relax the hard node affinity terms",
            ],
        }
