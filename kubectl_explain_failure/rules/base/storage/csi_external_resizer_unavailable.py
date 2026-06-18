from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class CSIExternalResizerUnavailableRule(FailureRule):
    """
    Detects PVC expansion failures caused by an unavailable CSI external-resizer.

    Real-world behavior:
    - PVC expansion requires the CSI external-resizer sidecar.
    - If the resizer Deployment/Pod is unavailable, expansion requests remain
      pending indefinitely.
    - PVCs often show Resizing/FileSystemResizePending conditions.
    - Events commonly contain:
          waiting for external resizer
          external-resizer is not running
          did not find a plugin capable of expanding
          resize operation failed
    - Controller pods may be CrashLooping, unavailable, unscheduled, or missing.

    Exclusions:
    - Storage backend capacity exhaustion
    - Unsupported volume expansion
    - Filesystem resize pending after successful controller expansion
    - PVC provisioning failures unrelated to expansion
    """

    name = "CSIExternalResizerUnavailable"
    category = "Storage"
    severity = "High"
    priority = 78
    deterministic = True

    phases = ["Pending", "Running"]

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "pvc",
            "storageclass",
            "pod",
            "deployment",
            "statefulset",
        ],
    }

    blocks = [
        "PVCExpansionPending",
        "PVCResizeStuck",
    ]

    WINDOW_MINUTES = 60

    RESIZER_IDENTIFIERS = (
        "external-resizer",
        "csi-resizer",
        "external resizer",
    )

    PVC_RESIZE_MARKERS = (
        "waiting for an external controller to expand this pvc",
        "waiting for external resizer",
        "external-resizer",
        "external resizer",
        "resize volume",
        "expand volume",
        "volume expansion",
        "filesystemresizepending",
        "resizing",
    )

    RESIZER_FAILURE_MARKERS = (
        "crashloopbackoff",
        "back-off restarting failed container",
        "failed",
        "leader election lost",
        "connection refused",
        "timed out",
        "panic",
        "error syncing claim",
        "unable to expand volume",
        "failed to expand volume",
        "rpc error",
        "permission denied",
    )

    RESIZER_WAITING_REASONS = {
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "ErrImagePull",
        "CreateContainerError",
        "CreateContainerConfigError",
        "RunContainerError",
        "ContainerCannotRun",
    }

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _object_name(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("name") or "")

    def _identity_text(self, obj: dict[str, Any]) -> str:
        metadata = obj.get("metadata", {}) or {}
        labels = metadata.get("labels", {}) or {}

        parts = [
            str(metadata.get("name") or ""),
            str(metadata.get("namespace") or ""),
        ]

        parts.extend(f"{k}={v}" for k, v in labels.items())

        spec = obj.get("spec", {}) or {}
        status = obj.get("status", {}) or {}

        for container in (
            spec.get("containers", [])
            + spec.get("initContainers", [])
            + status.get("containerStatuses", [])
        ):
            if isinstance(container, dict):
                parts.append(str(container.get("name") or ""))

        return " ".join(parts).lower()

    def _is_resizer_object(self, obj: dict[str, Any]) -> bool:
        text = self._identity_text(obj)
        return any(token in text for token in self.RESIZER_IDENTIFIERS)

    def _pod_ready(self, pod_obj: dict[str, Any]) -> bool:
        conditions = pod_obj.get("status", {}).get("conditions", []) or []

        return any(
            cond.get("type") == "Ready" and cond.get("status") == "True"
            for cond in conditions
        )

    def _degraded_resizer_pods(
        self,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        degraded = []

        for pod_obj in context.get("objects", {}).get("pod", {}).values():
            if not isinstance(pod_obj, dict):
                continue

            if not self._is_resizer_object(pod_obj):
                continue

            status = pod_obj.get("status", {}) or {}

            if status.get("phase") not in {"Running", "Succeeded"}:
                degraded.append(pod_obj)
                continue

            if not self._pod_ready(pod_obj):
                degraded.append(pod_obj)
                continue

            for container in status.get("containerStatuses", []) or []:
                waiting = container.get("state", {}).get("waiting", {})
                terminated = container.get("state", {}).get("terminated", {})

                if waiting.get("reason") in self.RESIZER_WAITING_REASONS:
                    degraded.append(pod_obj)
                    break

                if terminated and int(terminated.get("exitCode", 0) or 0) != 0:
                    degraded.append(pod_obj)
                    break

        return degraded

    def _deployment_signal(
        self,
        context: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        for deploy in context.get("objects", {}).get("deployment", {}).values():
            if not isinstance(deploy, dict):
                continue

            if not self._is_resizer_object(deploy):
                continue

            status = deploy.get("status", {}) or {}

            replicas = int(status.get("replicas", 0) or 0)
            available = int(status.get("availableReplicas", 0) or 0)
            ready = int(status.get("readyReplicas", 0) or 0)

            if replicas > 0 and (available < replicas or ready < replicas):
                return (
                    deploy,
                    (
                        f"CSI external-resizer deployment unavailable "
                        f"(ready={ready}, available={available}, replicas={replicas})"
                    ),
                )

        return None, None

    def _pvc_resize_signal(
        self,
        context: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, str | None]:
        for pvc in context.get("objects", {}).get("pvc", {}).values():
            if not isinstance(pvc, dict):
                continue

            conditions = pvc.get("status", {}).get("conditions", []) or []

            for condition in conditions:
                cond_type = str(condition.get("type") or "")
                if cond_type in {"Resizing", "FileSystemResizePending"}:
                    return (
                        pvc,
                        f"PVC condition indicates expansion is pending ({cond_type})",
                    )

        return None, None

    def _resizer_failure_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        events = timeline.events_within_window(self.WINDOW_MINUTES)

        failures = []

        for event in events:
            text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

            if any(id_ in text for id_ in self.RESIZER_IDENTIFIERS):
                if any(marker in text for marker in self.RESIZER_FAILURE_MARKERS):
                    failures.append(event)

        return failures

    def _resize_events(
        self,
        timeline: Timeline,
    ) -> list[dict[str, Any]]:
        events = timeline.events_within_window(self.WINDOW_MINUTES)

        matches = []

        for event in events:
            text = (f"{self._reason(event)} " f"{self._message(event)}").lower()

            if any(marker in text for marker in self.PVC_RESIZE_MARKERS):
                matches.append(event)

        return matches

    def _candidate(
        self,
        pod: dict[str, Any],
        timeline: Timeline,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        resize_events = self._resize_events(timeline)

        pvc_obj, pvc_signal = self._pvc_resize_signal(context)

        if not resize_events and not pvc_signal:
            return None

        degraded_resizers = self._degraded_resizer_pods(context)
        deployment, deployment_signal = self._deployment_signal(context)
        resizer_failures = self._resizer_failure_events(timeline)

        if not degraded_resizers and not deployment_signal and not resizer_failures:
            return None

        object_evidence: dict[str, list[str]] = {}
        evidence_signals: list[str] = []

        if pvc_obj and pvc_signal:
            pvc_name = self._object_name(pvc_obj)
            object_evidence[f"pvc:{pvc_name}"] = [pvc_signal]
            evidence_signals.append(pvc_signal)

        for pod_obj in degraded_resizers[:3]:
            pod_name = self._object_name(pod_obj)
            object_evidence[f"pod:{pod_name}"] = [
                "CSI external-resizer pod is degraded"
            ]
            evidence_signals.append(
                f"CSI external-resizer pod {pod_name} is not Ready or failing"
            )

        if deployment_signal:
            deploy_name = self._object_name(deployment or {})
            if deploy_name:
                object_evidence[f"deployment:{deploy_name}"] = [deployment_signal]
            evidence_signals.append(deployment_signal)

        if resizer_failures:
            latest = self._message(resizer_failures[-1])
            object_evidence.setdefault(
                "timeline:external-resizer",
                [],
            ).append(latest)
            evidence_signals.append(f"Recent external-resizer failure event: {latest}")

        return {
            "resize_events": resize_events,
            "resizer_failures": resizer_failures,
            "signals": list(dict.fromkeys(evidence_signals)),
            "object_evidence": object_evidence,
        }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")

        return (
            isinstance(timeline, Timeline)
            and self._candidate(pod, timeline, context) is not None
        )

    def explain(self, pod, events, context):
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            raise ValueError("CSIExternalResizerUnavailable requires Timeline context")

        candidate = self._candidate(
            pod,
            timeline,
            context,
        )

        if candidate is None:
            raise ValueError(
                "CSIExternalResizerUnavailable explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_EXPANSION_REQUESTED",
                    message="A PersistentVolumeClaim expansion operation is pending",
                    role="runtime_context",
                ),
                Cause(
                    code="CSI_EXTERNAL_RESIZER_UNAVAILABLE",
                    message="CSI external-resizer controller is unavailable or unhealthy",
                    role="infrastructure_root",
                    blocking=True,
                ),
                Cause(
                    code="PVC_EXPANSION_CANNOT_PROGRESS",
                    message="The storage expansion workflow cannot continue without a functioning external-resizer",
                    role="workload_symptom",
                ),
            ]
        )

        resize_occurrences = sum(
            self._occurrences(e) for e in candidate["resize_events"]
        )

        evidence = [
            f"Pod {namespace}/{pod_name} depends on storage expansion that is not progressing",
            f"Observed {resize_occurrences} PVC expansion-related event occurrence(s) in the recent incident window",
        ]

        evidence.extend(candidate["signals"])

        confidence = 0.92

        if candidate["resizer_failures"] and candidate["object_evidence"]:
            confidence = 0.98
        elif candidate["object_evidence"]:
            confidence = 0.96

        return {
            "rule": self.name,
            "root_cause": "CSI external-resizer controller is unavailable",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                k: list(dict.fromkeys(v))
                for k, v in candidate["object_evidence"].items()
            },
            "likely_causes": [
                "The CSI external-resizer pod is CrashLooping or not Ready",
                "The CSI controller Deployment is unavailable or partially rolled out",
                "Leader election or controller-runtime failures prevent the resizer from processing PVC expansion requests",
                "RBAC or API access problems prevent the external-resizer from updating PVC/PV objects",
                "The CSI driver upgrade left the external-resizer sidecar unavailable",
            ],
            "suggested_checks": [
                "kubectl get pvc",
                "kubectl describe pvc <pvc-name>",
                "kubectl get pods -A | grep resizer",
                "kubectl logs <external-resizer-pod> -c csi-resizer",
                "kubectl describe deployment <csi-controller-deployment>",
                "kubectl get events --sort-by=.lastTimestamp",
                "Verify that the StorageClass allows volume expansion",
            ],
        }
