from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CSIPluginCrashLoopRule(FailureRule):
    """
    Detects explicit CSI controller/node plugin CrashLoopBackOff conditions.

    Real-world behavior:
    - the most reliable signal is when the target pod itself looks like a CSI
      component and is in CrashLoopBackOff
    - for non-CSI workloads, this rule only triggers when crash evidence is
      explicitly CSI-related; generic application crash loops are excluded
    """

    name = "CSIPluginCrashLoop"
    category = "Compound"
    priority = 90
    deterministic = True
    blocks = [
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
        "CSIControllerUnavailable",
        "CSIProvisioningFailed",
    ]
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": ["pvc", "storageclass"],
    }

    CSI_COMPONENT_MARKERS = (
        "csi",
        "external-provisioner",
        "external-attacher",
        "node-driver-registrar",
        "liveness-probe",
        "csi-node",
        "csi-controller",
    )

    STORAGE_FAILURE_REASONS = {
        "ProvisioningFailed",
        "FailedAttachVolume",
        "FailedMount",
    }

    def _pod_text(self, pod: dict) -> str:
        metadata = pod.get("metadata", {})
        labels = metadata.get("labels", {}) or {}
        spec_containers = pod.get("spec", {}).get("containers", []) or []
        statuses = pod.get("status", {}).get("containerStatuses", []) or []

        values = [
            metadata.get("name", ""),
            metadata.get("namespace", ""),
            *labels.keys(),
            *labels.values(),
            *[container.get("name", "") for container in spec_containers],
            *[status.get("name", "") for status in statuses],
        ]

        return " ".join(str(value).lower() for value in values if value)

    def _pod_looks_like_csi_component(self, pod: dict) -> bool:
        text = self._pod_text(pod)
        return any(marker in text for marker in self.CSI_COMPONENT_MARKERS)

    def _pod_is_crashlooping(self, pod: dict, timeline) -> bool:
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = status.get("state", {}).get("waiting", {}) or {}
            if waiting.get("reason") == "CrashLoopBackOff":
                return True

        for event in timeline.raw_events:
            reason = str(event.get("reason", "")).lower()
            message = str(event.get("message", "")).lower()
            if (
                reason == "backoff"
                and "back-off restarting failed container" in message
            ):
                return True

        return False

    def _storage_failures_point_to_csi(self, timeline) -> bool:
        for event in timeline.raw_events:
            if event.get("reason") not in self.STORAGE_FAILURE_REASONS:
                continue

            message = str(event.get("message", "")).lower()
            if any(
                marker in message
                for marker in (
                    "csi",
                    "rpc error",
                    "driver not found",
                    "connection refused",
                )
            ):
                return True

        return False

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        if not self._pod_is_crashlooping(pod, timeline):
            return False

        if self._pod_looks_like_csi_component(pod):
            return True

        return self._storage_failures_point_to_csi(timeline)

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        is_csi_component = self._pod_looks_like_csi_component(pod)

        chain = CausalChain(
            causes=[
                Cause(
                    code="CSI_PLUGIN_CRASH",
                    message="CSI driver/plugin container repeatedly crashes",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="VOLUME_UNAVAILABLE",
                    message="Persistent volumes managed by CSI remain unavailable",
                    role="volume_context",
                ),
                Cause(
                    code="POD_PENDING_OR_FAILING",
                    message="Pod fails operations dependent on CSI-managed storage",
                    role="workload_symptom",
                ),
                Cause(
                    code="CRASHLOOP_BACKOFF",
                    message="Kubernetes observes repeated back-off restarts",
                    role="control_loop",
                ),
            ]
        )

        root_cause = (
            "CSI plugin pod is crash-looping"
            if is_csi_component
            else "CSI plugin crash-loop is preventing storage operations"
        )

        object_evidence = {
            f"pod:{pod_name}": [
                (
                    "Target pod appears to be a CSI component in CrashLoopBackOff"
                    if is_csi_component
                    else "Pod is affected by CSI-related storage failures while CSI components are crash-looping"
                )
            ]
        }

        return {
            "root_cause": root_cause,
            "confidence": 0.92,
            "causes": chain,
            "evidence": [
                (
                    "Pod identity or labels indicate a CSI controller or node plugin"
                    if is_csi_component
                    else "CrashLoopBackOff is only reported when crash evidence is explicitly CSI-related"
                ),
                "Back-off restarts are present for the crashing component",
            ],
            "likely_causes": [
                "CSI driver misconfiguration or version mismatch",
                "Storage endpoint or network issues affecting the CSI plugin",
                "Resource starvation causing the CSI component to restart",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl logs <csi-plugin-pod> -c <csi-container>",
                "kubectl get pods -n kube-system",
                "Inspect CSI driver Deployment or DaemonSet events",
            ],
            "blocking": True,
            "object_evidence": object_evidence,
        }
