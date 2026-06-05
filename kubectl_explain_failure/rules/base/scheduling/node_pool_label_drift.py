from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class NodePoolLabelDriftRule(FailureRule):
    """
    Detects Pods that became unschedulable because node pool labels drifted
    away from what the workload requires.

    Real-world behavior:
    - Managed Kubernetes platforms (EKS, GKE, AKS, OpenShift, Cluster API,
      Karpenter, autoscaled node groups, etc.) often rely on labels to
      represent node pools, capacity classes, environments, teams, hardware
      types, spot/on-demand placement, GPU pools, and workload isolation.
    - Pods frequently use nodeSelector or requiredDuringScheduling affinity
      against those labels.
    - When a node pool is recreated, upgraded, renamed, migrated, or labels
      are changed, existing workloads may suddenly become unschedulable even
      though cluster capacity exists.
    - Scheduler events typically surface as:
          "node(s) didn't match Pod's node affinity/selector"
      while nodes either:
          * no longer contain the required label
          * contain the label with different values
          * have only a subset of the previously expected values
    - This rule focuses specifically on label drift. Generic affinity and
      selector failures are handled by broader scheduling rules.
    """

    name = "NodePoolLabelDrift"
    category = "Scheduling"
    priority = 88
    deterministic = False

    phases = ["Pending"]

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
        ],
    }

    CACHE_KEY = "_node_pool_label_drift_candidate"
    WINDOW_MINUTES = 120

    NODEPOOL_LABEL_MARKERS = (
        "nodepool",
        "node-pool",
        "nodegroup",
        "node-group",
        "agentpool",
        "karpenter.sh",
        "eks.amazonaws.com",
        "cloud.google.com/gke-nodepool",
        "node.kubernetes.io/instance-type",
        "beta.kubernetes.io/instance-type",
    )

    SCHEDULER_MISMATCH_MARKERS = (
        "didn't match pod's node affinity",
        "didn't match pod affinity",
        "didn't match pod's node selector",
        "node(s) didn't match",
        "match node selector",
        "match pod affinity",
        "unschedulable",
    )

    def _node_objects(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        nodes = context.get("nodes")
        if isinstance(nodes, list):
            return [n for n in nodes if isinstance(n, dict)]

        node = context.get("node")
        if isinstance(node, list):
            return [n for n in node if isinstance(n, dict)]

        if isinstance(node, dict):
            return [node]

        return []

    def _event_text(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        component = source.get("component") if isinstance(source, dict) else source

        return " ".join(
            str(part or "")
            for part in (
                event.get("reason"),
                event.get("message"),
                component,
            )
        ).lower()

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

    def _required_selector_labels(
        self,
        pod: dict[str, Any],
    ) -> dict[str, set[str] | None]:
        """
        Returns required labels from:
        - spec.nodeSelector
        - requiredDuringSchedulingIgnoredDuringExecution node affinity

        Value meanings:
        - {"a"} = specific required value(s)
        - None = label existence required
        """
        labels: dict[str, set[str] | None] = {}

        spec = pod.get("spec", {}) or {}

        node_selector = spec.get("nodeSelector") or {}
        if isinstance(node_selector, dict):
            for key, value in node_selector.items():
                labels[str(key)] = {str(value)}

        affinity = (
            spec.get("affinity", {})
            .get("nodeAffinity", {})
            .get("requiredDuringSchedulingIgnoredDuringExecution", {})
        )

        terms = affinity.get("nodeSelectorTerms", []) or []

        for term in terms:
            if not isinstance(term, dict):
                continue

            for expr in term.get("matchExpressions", []) or []:
                if not isinstance(expr, dict):
                    continue

                key = str(expr.get("key", "")).strip()
                operator = str(expr.get("operator", "")).strip()
                values = {str(v) for v in (expr.get("values") or []) if str(v).strip()}

                if not key:
                    continue

                if operator == "In":
                    labels[key] = values
                elif operator == "Exists":
                    labels[key] = None

        return labels

    def _is_nodepool_label(self, key: str) -> bool:
        lowered = key.lower()

        return any(marker in lowered for marker in self.NODEPOOL_LABEL_MARKERS)

    def _event_mentions_pod(
        self,
        event: dict[str, Any],
        *,
        pod_name: str,
        pod_namespace: str,
    ) -> bool:
        involved = event.get("involvedObject") or {}

        if isinstance(involved, dict):
            if (
                involved.get("kind") == "Pod"
                and involved.get("name") == pod_name
                and (
                    involved.get("namespace") == pod_namespace
                    or not involved.get("namespace")
                )
            ):
                return True

        text = " ".join(
            str(part or "")
            for part in (
                event.get("reason"),
                event.get("message"),
            )
        ).lower()

        return pod_name.lower() in text

    def _scheduler_mismatch_events(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        pod_name = str(pod.get("metadata", {}).get("name") or "<unknown>")
        namespace = str(pod.get("metadata", {}).get("namespace") or "default")

        matches = []

        for event in self._candidate_events(events, context):
            if not isinstance(event, dict):
                continue

            text = self._event_text(event)

            if not any(marker in text for marker in self.SCHEDULER_MISMATCH_MARKERS):
                continue

            if self._event_mentions_pod(
                event,
                pod_name=pod_name,
                pod_namespace=namespace,
            ):
                matches.append(event)

        return matches

    def _detect_label_drift(
        self,
        required_labels: dict[str, set[str] | None],
        nodes: list[dict[str, Any]],
    ) -> list[str]:
        """
        Detect real drift patterns.

        We only trigger when:
        - workload requires a nodepool-related label
        - cluster nodes no longer satisfy that requirement
        """

        signals: list[str] = []

        if not nodes:
            return signals

        for label, required_values in required_labels.items():
            if not self._is_nodepool_label(label):
                continue

            nodes_with_label = 0
            matching_nodes = 0

            observed_values: set[str] = set()

            for node in nodes:
                node_labels = (node.get("metadata", {}).get("labels", {})) or {}

                if label not in node_labels:
                    continue

                nodes_with_label += 1

                node_value = str(node_labels[label])
                observed_values.add(node_value)

                if required_values is None:
                    matching_nodes += 1
                elif node_value in required_values:
                    matching_nodes += 1

            if nodes_with_label == 0:
                signals.append(
                    f"Required node-pool label '{label}' is absent from all nodes"
                )
                continue

            if matching_nodes == 0:
                expected = (
                    ", ".join(sorted(required_values))
                    if required_values
                    else "<exists>"
                )

                observed = ", ".join(sorted(observed_values)) or "<none>"

                signals.append(
                    f"Node-pool label '{label}' drifted: expected "
                    f"[{expected}] but cluster currently advertises "
                    f"[{observed}]"
                )

        return signals

    def _candidate(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        if get_pod_phase(pod) != "Pending":
            return None

        required_labels = self._required_selector_labels(pod)

        nodepool_constraints = {
            k: v for k, v in required_labels.items() if self._is_nodepool_label(k)
        }

        if not nodepool_constraints:
            return None

        nodes = self._node_objects(context)

        drift_signals = self._detect_label_drift(
            nodepool_constraints,
            nodes,
        )

        if not drift_signals:
            return None

        scheduler_events = self._scheduler_mismatch_events(
            pod,
            events,
            context,
        )

        return {
            "required_labels": nodepool_constraints,
            "drift_signals": drift_signals,
            "events": scheduler_events,
        }

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, events, context)

        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False

        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(pod, events, context)

        if candidate is None:
            raise ValueError("NodePoolLabelDrift explain() called without match")

        pod_name = str(pod.get("metadata", {}).get("name") or "<unknown>")
        namespace = str(pod.get("metadata", {}).get("namespace") or "default")

        required_labels = candidate["required_labels"]
        drift_signals = candidate["drift_signals"]
        matching_events = candidate["events"]

        label_summary = ", ".join(
            f"{label}=" f"{'*' if values is None else '|'.join(sorted(values))}"
            for label, values in required_labels.items()
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_REQUIRES_NODEPOOL_LABELS",
                    message=(f"Pod requires node-pool labels: {label_summary}"),
                    role="workload_context",
                ),
                Cause(
                    code="NODEPOOL_LABEL_DRIFT",
                    message=(
                        "Required node-pool labels no longer match "
                        "current node labels"
                    ),
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_UNSCHEDULABLE",
                    message=(
                        "Scheduler cannot find a node matching the "
                        "required node-pool labels"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod phase={get_pod_phase(pod)}",
            f"Required node-pool labels={label_summary}",
            *drift_signals,
        ]

        event_messages = []

        for event in matching_events:
            message = event.get("message")
            if message:
                event_messages.append(str(message))

        if event_messages:
            evidence.append(
                f"Scheduler mismatch event observed {len(event_messages)} time(s)"
            )
            evidence.extend(event_messages[:2])

        object_evidence = {
            f"pod:{namespace}/{pod_name}": [
                f"Requires node-pool labels: {label_summary}",
                *event_messages[:3],
            ]
        }

        for label in required_labels:
            object_evidence[f"label:{label}"] = drift_signals

        confidence = 0.93
        if event_messages:
            confidence = 0.97

        return {
            "rule": self.name,
            "root_cause": (
                "Node pool labels drifted from the labels required by the Pod"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                key: list(dict.fromkeys(values))
                for key, values in object_evidence.items()
            },
            "likely_causes": [
                "Managed node pool was recreated with different labels",
                "Node group or node pool was renamed",
                "Karpenter provisioning configuration changed label values",
                "Cluster upgrade replaced nodes and dropped custom labels",
                "Platform-specific node-pool labels changed after migration",
                "Workload still targets a retired node pool name",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get nodes --show-labels",
                "kubectl get node -o json | jq '.items[].metadata.labels'",
                "Compare current node labels with workload nodeSelector and nodeAffinity requirements",
                "Review recent node pool, node group, Karpenter, Cluster API, EKS, GKE, or AKS changes",
                "Check scheduler FailedScheduling events for affinity and selector mismatch details",
            ],
        }
