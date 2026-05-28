from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.model import get_pod_phase
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class RuntimeClassHandlerUnavailableRule(FailureRule):
    """
    Detects Pods that reference an existing RuntimeClass whose runtime handler
    is unavailable on candidate nodes.

    Real-world behavior:
    - RuntimeClass exists, so this is NOT RuntimeClassNotFound
    - kube-scheduler may successfully bind the Pod to a node
    - kubelet/container runtime then fails sandbox creation because:
        * runtime handler is not configured in containerd/CRI-O
        * Kata/gVisor runtime is missing
        * GPU/confidential runtime was not installed
        * runtimeClass.handler differs across node pools
        * RuntimeClass scheduling constraints drifted from runtime deployment
    - Pods typically fail with:
        * FailedCreatePodSandBox
        * Failed
        * CreateContainerError
        * sandbox creation failures
        * "RuntimeHandler not supported"
        * "no runtime for"
    """

    name = "RuntimeClassHandlerUnavailable"
    category = "Compound"
    priority = 84
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "context": ["timeline"],
        "optional_objects": [
            "runtimeclass",
            "node",
        ],
    }

    blocks = [
        "FailedCreatePodSandBox",
        "CreateContainerError",
        "ContainerRuntimeUnavailable",
        "PendingUnschedulable",
        "RepeatedSandboxCreationFailure",
    ]

    window_minutes = 30
    CACHE_KEY = "_runtimeclass_handler_unavailable_candidate"

    RUNTIME_FAILURE_REASONS = {
        "FailedCreatePodSandBox",
        "Failed",
        "SandboxChanged",
    }

    HANDLER_ERROR_MARKERS = (
        "runtimehandler",
        "runtime handler",
        "no runtime for",
        "handler not supported",
        "failed to find runtime handler",
        "runtime class handler",
        "failed to create sandbox",
        "failed to setup sandbox",
        "failed to create pod sandbox",
        "unsupported runtime",
        "unknown runtime handler",
        "kata",
        "gvisor",
        "runsc",
        "nvidia",
        "confidential",
        "wasm",
    )

    NODE_RUNTIME_MARKERS = (
        "containerd",
        "cri-o",
        "runtime",
        "sandbox",
    )

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component") or "").lower()
        return str(source or "").lower()

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        ts = (
            event.get("eventTime")
            or event.get("lastTimestamp")
            or event.get("firstTimestamp")
            or event.get("timestamp")
        )

        if not isinstance(ts, str):
            return None

        try:
            return parse_time(ts)
        except Exception:
            return None

    def _runtimeclass_name(self, pod: dict[str, Any]) -> str | None:
        spec = pod.get("spec", {}) or {}
        runtime_class = spec.get("runtimeClassName")

        if runtime_class:
            return str(runtime_class)

        return None

    def _runtimeclass_object(
        self,
        context: dict[str, Any],
        runtimeclass_name: str,
    ) -> dict[str, Any] | None:
        runtimeclasses = context.get("objects", {}).get("runtimeclass", {}) or {}

        obj = runtimeclasses.get(runtimeclass_name)

        if isinstance(obj, dict):
            return obj

        for fallback_name, candidate in runtimeclasses.items():
            if not isinstance(candidate, dict):
                continue

            metadata_name = str(
                candidate.get("metadata", {}).get("name") or fallback_name
            )

            if metadata_name == runtimeclass_name:
                return candidate

        return None

    def _runtime_handler(self, runtimeclass: dict[str, Any]) -> str:
        return str(runtimeclass.get("handler") or "").strip()

    def _is_runtime_handler_failure(self, event: dict[str, Any]) -> bool:
        reason = self._reason(event)
        message = self._message(event).lower()
        source = self._source_component(event)

        if reason not in self.RUNTIME_FAILURE_REASONS and "sandbox" not in message:
            return False

        if not any(marker in message for marker in self.HANDLER_ERROR_MARKERS):
            return False

        if source and not any(marker in source for marker in self.NODE_RUNTIME_MARKERS):
            # kubelet often emits these without explicit runtime source,
            # so only reject obviously unrelated components
            if source not in {"kubelet", ""}:
                return False

        return True

    def _recent_runtime_failures(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        return [
            event
            for event in timeline.events_within_window(self.window_minutes)
            if self._is_runtime_handler_failure(event)
        ]

    def _scheduled_after_failure(
        self,
        timeline: Timeline,
        after: datetime | None,
    ) -> bool:
        for event in timeline.events:
            if event.get("reason") != "Started":
                continue

            event_time = self._event_time(event)

            if after is None or event_time is None:
                return True

            if event_time >= after:
                return True

        return False

    def _node_runtime_signal(
        self,
        context: dict[str, Any],
        handler: str,
    ) -> list[str]:
        """
        Detect node-level evidence suggesting runtime handler mismatch.

        This intentionally uses heuristics because Kubernetes Node objects
        normally do not expose configured runtime handlers directly.
        """

        signals: list[str] = []

        nodes = context.get("objects", {}).get("node", {}) or {}

        normalized_handler = handler.lower()

        for _, node in nodes.items():
            if not isinstance(node, dict):
                continue

            metadata = node.get("metadata", {}) or {}
            labels = metadata.get("labels", {}) or {}
            annotations = metadata.get("annotations", {}) or {}

            combined = " ".join([str(labels), str(annotations)]).lower()

            node_name = str(metadata.get("name") or "<node>")

            if normalized_handler and normalized_handler not in combined:
                if any(
                    marker in normalized_handler
                    for marker in (
                        "kata",
                        "gvisor",
                        "runsc",
                        "nvidia",
                        "wasm",
                        "confidential",
                    )
                ):
                    signals.append(
                        f"Node '{node_name}' does not advertise runtime handler '{handler}' in labels/annotations"
                    )

        return signals

    def matches(self, pod, events, context) -> bool:
        phase = get_pod_phase(pod)

        if phase not in {"Pending", "Running"}:
            return False

        runtimeclass_name = self._runtimeclass_name(pod)

        if not runtimeclass_name:
            return False

        runtimeclass = self._runtimeclass_object(
            context,
            runtimeclass_name,
        )

        # RuntimeClass missing belongs to RuntimeClassNotFound
        if runtimeclass is None:
            return False

        handler = self._runtime_handler(runtimeclass)

        if not handler:
            return False

        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            return False

        runtime_failures = self._recent_runtime_failures(timeline)

        if not runtime_failures:
            return False

        representative = runtime_failures[-1]
        failure_time = self._event_time(representative)

        if self._scheduled_after_failure(timeline, failure_time):
            return False

        context[self.CACHE_KEY] = {
            "runtimeclass_name": runtimeclass_name,
            "handler": handler,
            "runtimeclass": runtimeclass,
            "runtime_failures": runtime_failures,
            "node_signals": self._node_runtime_signal(context, handler),
        }

        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY)

        if candidate is None:
            raise ValueError(
                "RuntimeClassHandlerUnavailable explain() called without match"
            )

        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            raise ValueError("RuntimeClassHandlerUnavailable requires Timeline context")

        metadata = pod.get("metadata", {}) or {}

        pod_name = str(metadata.get("name") or "<unknown>")
        namespace = str(metadata.get("namespace") or "default")

        runtimeclass_name = candidate["runtimeclass_name"]
        handler = candidate["handler"]

        runtime_failures = candidate["runtime_failures"]
        representative = runtime_failures[-1]

        failure_message = self._message(representative)
        failure_reason = self._reason(representative)

        duration_seconds = timeline.duration_between(
            lambda event: self._is_runtime_handler_failure(event)
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_REQUESTS_RUNTIMECLASS",
                    message=f"Pod explicitly requests RuntimeClass '{runtimeclass_name}'",
                    role="runtime_context",
                ),
                Cause(
                    code="RUNTIME_HANDLER_UNAVAILABLE",
                    message=f"Runtime handler '{handler}' is not configured or available on candidate nodes",
                    role="node_runtime_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_SANDBOX_CREATION_FAILED",
                    message="Container runtime could not create the Pod sandbox using the requested runtime handler",
                    role="runtime_intermediate",
                ),
                Cause(
                    code="POD_CANNOT_START",
                    message="Pod cannot start containers because sandbox initialization repeatedly fails",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} requests RuntimeClass '{runtimeclass_name}'",
            f"RuntimeClass '{runtimeclass_name}' uses handler '{handler}'",
            f"Observed runtime sandbox failure: {failure_reason}: {failure_message}",
            "RuntimeClass exists, but the runtime handler appears unavailable on cluster nodes",
        ]

        if duration_seconds:
            evidence.append(
                f"Runtime sandbox failures persisted for {duration_seconds / 60.0:.1f} minutes"
            )

        evidence.extend(candidate["node_signals"])

        object_evidence = {
            f"pod:{pod_name}": [
                f"Pod requests RuntimeClass '{runtimeclass_name}'",
                f"Sandbox/runtime failure: {failure_message}",
            ],
            f"runtimeclass:{runtimeclass_name}": [
                f"RuntimeClass exists and specifies handler '{handler}'",
            ],
        }

        if candidate["node_signals"]:
            object_evidence["node:runtime-support"] = candidate["node_signals"]

        return {
            "root_cause": f"RuntimeClass handler '{handler}' is unavailable on cluster nodes",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                f"The '{handler}' runtime handler is not configured in containerd or CRI-O",
                "Kata Containers, gVisor, WASM, GPU runtime, or confidential-compute runtime is not installed on the node",
                "RuntimeClass references a handler name that differs from the node runtime configuration",
                "Pod was scheduled onto a node pool that does not support the requested runtime",
                "Container runtime restart or upgrade removed the configured runtime handler",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                f"kubectl get runtimeclass {runtimeclass_name} -o yaml",
                "Inspect kubelet and container runtime logs on the target node",
                "Verify the runtime handler exists in containerd or CRI-O configuration",
                "Confirm the requested runtime is installed on all eligible nodes",
                "Check node selectors, taints, and RuntimeClass scheduling constraints",
            ],
        }
