from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class PodFitsOnlyTerminatingNodesRule(FailureRule):
    """
    Detect Pods whose scheduling constraints only match nodes that are
    currently terminating, draining, shutting down, or being deleted.

    Real-world behavior:
    - During node pool upgrades or autoscaler scale-down operations,
      the only nodes satisfying a Pod's selectors/affinity may already
      be leaving the cluster.
    - Scheduler failures commonly mention node deletion, shutdown,
      draining, or autoscaler removal.
    - Nodes with deletionTimestamp set are no longer valid scheduling
      targets even if labels and resources still match.
    """

    name = "PodFitsOnlyTerminatingNodes"
    category = "Scheduling"
    priority = 92
    deterministic = False

    phases = ["Pending", "Unknown"]

    blocks = [
        "FailedScheduling",
        "PendingUnschedulable",
        "NodeSelectorMismatch",
        "NodeAffinityRequiredMismatch",
        "AffinityUnsatisfiable",
        "ClusterAutoscalerScaleUpFailed",
    ]

    requires = {
        "pod": True,
        "optional_objects": [
            "node",
            "nodes",
        ],
    }

    CACHE_KEY = "_pod_fits_only_terminating_nodes_candidate"
    WINDOW_MINUTES = 60

    TERMINATING_MARKERS = (
        "being deleted",
        "marked for deletion",
        "terminating",
        "shutting down",
        "shutdown",
        "draining",
        "drained",
        "node deletion",
        "deleting node",
        "node is deleting",
        "node is being deleted",
        "cluster autoscaler deleting",
        "scale-down",
        "scaledown",
        "marked for removal",
    )

    def _message(self, value: Any) -> str:
        return str(value or "").strip()

    def _namespace(self, obj: dict[str, Any]) -> str:
        return self._message(obj.get("metadata", {}).get("namespace")) or "default"

    def _object_list(
        self,
        context: dict[str, Any],
        *names: str,
    ) -> list[dict[str, Any]]:
        objects = context.get("objects", {}) or {}
        results: list[dict[str, Any]] = []

        for name in names:
            raw = objects.get(name)

            if isinstance(raw, list):
                results.extend(obj for obj in raw if isinstance(obj, dict))

            elif isinstance(raw, dict):
                if "metadata" in raw:
                    results.append(raw)
                else:
                    results.extend(obj for obj in raw.values() if isinstance(obj, dict))

        return results

    def _candidate_events(
        self,
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        timeline = context.get("timeline")

        if isinstance(timeline, Timeline):
            recent = timeline.events_within_window(self.WINDOW_MINUTES)
            return recent or timeline.events

        return events or []

    def _node_is_terminating(
        self,
        node: dict[str, Any],
    ) -> bool:
        metadata = node.get("metadata", {}) or {}

        if metadata.get("deletionTimestamp"):
            return True

        for condition in node.get("status", {}).get("conditions", []) or []:
            if not isinstance(condition, dict):
                continue

            cond_type = self._message(condition.get("type")).lower()

            reason = self._message(condition.get("reason")).lower()

            message = self._message(condition.get("message")).lower()

            combined = f"{cond_type} {reason} {message}"

            if any(marker in combined for marker in self.TERMINATING_MARKERS):
                return True

        return False

    def _terminating_nodes(
        self,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        return [
            node
            for node in self._object_list(
                context,
                "node",
                "nodes",
            )
            if self._node_is_terminating(node)
        ]

    def _match_expression(
        self,
        node_labels: dict[str, str],
        expression: dict[str, Any],
    ) -> bool:
        key = expression.get("key")
        operator = expression.get("operator")
        values = expression.get("values") or []

        if not isinstance(key, str):
            return False

        present = key in node_labels
        node_value = node_labels.get(key)

        if operator == "In":
            return present and node_value in values

        if operator == "NotIn":
            return (not present) or node_value not in values

        if operator == "Exists":
            return present

        if operator == "DoesNotExist":
            return not present

        if operator == "Gt":
            try:
                if not present or node_value is None or not values:
                    return False
                return int(node_value) > int(str(values[0]))
            except (TypeError, ValueError):
                return False

        if operator == "Lt":
            try:
                if not present or node_value is None or not values:
                    return False
                return int(node_value) < int(str(values[0]))
            except (TypeError, ValueError):
                return False

        return False

    def _node_matches_required_affinity(
        self,
        node: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        affinity = pod.get("spec", {}).get("affinity", {}).get("nodeAffinity", {})

        required = affinity.get("requiredDuringSchedulingIgnoredDuringExecution")

        if not isinstance(required, dict):
            return True

        terms = required.get("nodeSelectorTerms") or []

        if not terms:
            return True

        labels = node.get("metadata", {}).get("labels", {}) or {}

        # OR across terms
        for term in terms:
            expressions = term.get("matchExpressions") or []

            # AND inside term
            if all(
                self._match_expression(labels, expr)
                for expr in expressions
                if isinstance(expr, dict)
            ):
                return True

        return False

    def _node_matches_node_selector(
        self,
        node: dict[str, Any],
        pod: dict[str, Any],
    ) -> bool:
        selector = pod.get("spec", {}).get("nodeSelector", {}) or {}

        labels = node.get("metadata", {}).get("labels", {}) or {}

        for key, value in selector.items():
            if labels.get(key) != value:
                return False

        return True

    def _eligible_nodes(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        eligible = []

        for node in self._object_list(
            context,
            "node",
            "nodes",
        ):
            if not self._node_matches_node_selector(
                node,
                pod,
            ):
                continue

            if not self._node_matches_required_affinity(
                node,
                pod,
            ):
                continue

            eligible.append(node)

        return eligible

    def _scheduler_events(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        pod_name = self._message(pod.get("metadata", {}).get("name"))

        namespace = self._namespace(pod)

        matches = []

        for event in self._candidate_events(
            events,
            context,
        ):
            if not isinstance(event, dict):
                continue

            involved = event.get("involvedObject") or {}

            if involved.get("kind") == "Pod" and involved.get("name") != pod_name:
                continue

            if involved.get("namespace") and involved.get("namespace") != namespace:
                continue

            message = self._message(event.get("message"))

            combined = (f"{event.get('reason') or ''} " f"{message}").lower()

            if any(marker in combined for marker in self.TERMINATING_MARKERS):
                matches.append(event)

        return matches

    def _candidate(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:

        if pod.get("spec", {}).get("schedulingGates"):
            return None

        if get_pod_phase(pod) not in {
            "Pending",
            "Unknown",
        }:
            return None

        eligible_nodes = self._eligible_nodes(
            pod,
            context,
        )

        terminating_nodes = [n for n in eligible_nodes if self._node_is_terminating(n)]

        active_nodes = [n for n in eligible_nodes if not self._node_is_terminating(n)]

        matching_events = self._scheduler_events(
            pod,
            events,
            context,
        )

        all_matching_nodes_terminating = (
            bool(eligible_nodes) and bool(terminating_nodes) and not active_nodes
        )

        if not (all_matching_nodes_terminating or matching_events):
            return None

        return {
            "eligible_nodes": eligible_nodes,
            "terminating_nodes": terminating_nodes,
            "active_nodes": active_nodes,
            "events": matching_events,
            "proven": all_matching_nodes_terminating,
        }

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(
            pod,
            events,
            context,
        )

        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False

        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(
            pod,
            events,
            context,
        )

        if candidate is None:
            raise ValueError(
                "PodFitsOnlyTerminatingNodes explain() called without match"
            )

        pod_name = self._message(pod.get("metadata", {}).get("name")) or "<unknown>"

        namespace = self._namespace(pod)

        terminating_nodes = candidate["terminating_nodes"]

        node_names = [
            self._message(n.get("metadata", {}).get("name"))
            for n in terminating_nodes
            if self._message(n.get("metadata", {}).get("name"))
        ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_HAS_RESTRICTIVE_PLACEMENT",
                    message=(
                        "Pod placement constraints significantly limit eligible nodes"
                    ),
                    role="workload_context",
                ),
                Cause(
                    code="ELIGIBLE_NODES_TERMINATING",
                    message=("Nodes matching the Pod are terminating or being deleted"),
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_CANNOT_BE_SCHEDULED",
                    message=("Scheduler cannot place Pod on nodes leaving the cluster"),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod phase={get_pod_phase(pod)}",
        ]

        if candidate.get("proven"):
            evidence.append(
                f"All {len(candidate['eligible_nodes'])} node(s) matching "
                "Pod nodeSelector/nodeAffinity are terminating"
            )

        object_evidence: dict[str, list[str]] = {
            f"pod:{namespace}/{pod_name}": [],
        }

        for node_name in node_names:
            evidence.append(f"Node {node_name} is terminating")

            object_evidence[f"node:{node_name}"] = [
                "Node matches Pod scheduling constraints",
                "Node has deletion or shutdown indicators",
            ]

        event_messages = [
            self._message(e.get("message"))
            for e in candidate["events"]
            if self._message(e.get("message"))
        ]

        evidence.extend(event_messages[:3])

        if event_messages:
            object_evidence[f"pod:{namespace}/{pod_name}"].extend(event_messages[:3])

        confidence = 0.85

        if candidate.get("proven"):
            confidence = 0.98

        if candidate.get("proven") and event_messages:
            confidence = 0.99

        elif node_names and event_messages:
            confidence = 0.94

        return {
            "rule": self.name,
            "root_cause": ("Pod only fits nodes that are terminating or being deleted"),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                k: list(dict.fromkeys(v)) for k, v in object_evidence.items()
            },
            "likely_causes": [
                "Node pool upgrade is draining matching nodes",
                "Cluster Autoscaler is removing matching nodes",
                "Pod affinity or node selectors are overly restrictive",
                "Dedicated nodes for the workload are being deleted",
                "The only eligible nodes are shutting down",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get nodes",
                "kubectl get nodes -o yaml | grep deletionTimestamp",
                "kubectl describe node <node-name>",
                "Review node pool upgrade activity",
                "Review Cluster Autoscaler events and logs",
            ],
        }
