from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class RepeatedMountRetryRule(FailureRule):
    """
    Detects Pods that repeatedly fail volume mounts.

    Signals:
    - Multiple consecutive FailedMount events on the Pod
    - Duration exceeds a sustained threshold (~5 minutes)
    - Mount failure is persistent, not transient

    Interpretation:
    The Pod cannot mount one or more volumes due to persistent storage or CSI errors.
    Repeated retries indicate a deterministic mounting failure rather than transient delays.

    Scope:
    - Volume layer (CSI / kubelet mount)
    - Deterministic (object state + timeline duration)
    - Captures sustained mount failures (>3 consecutive failures)
    """

    name = "RepeatedMountRetry"
    category = "Temporal"
    priority = 90
    deterministic = True
    blocks = [
        "PodUnschedulable",
        "VolumeAttachFailed",
        "VolumeDetachFailed",
        "FailedMount",
    ]
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pvc", "pv"],
    }

    MOUNT_FAILURE_MARKERS = (
        "failedmount",
        "mountvolume",
        "attachvolume",
        "csi error",
    )

    EXCLUSION_MARKERS = (
        "already mounted",
        "successfully mounted",
        "unmounted",
    )

    MIN_CONSECUTIVE_FAILURES = 3
    MIN_DURATION_SECONDS = 300  # 5 minutes

    def _occurrences(self, event) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Filter FailedMount-like events
        mount_failures = [
            e
            for e in timeline.raw_events
            if any(
                marker in str(e.get("reason", "")).lower()
                or marker in str(e.get("message", "")).lower()
                for marker in self.MOUNT_FAILURE_MARKERS
            )
            and not any(
                marker in str(e.get("message", "")).lower()
                for marker in self.EXCLUSION_MARKERS
            )
        ]

        if len(mount_failures) < self.MIN_CONSECUTIVE_FAILURES:
            return False

        # Check sustained duration
        duration = timeline.duration_between(
            lambda e: any(
                marker in str(e.get("reason", "")).lower()
                or marker in str(e.get("message", "")).lower()
                for marker in self.MOUNT_FAILURE_MARKERS
            )
        )
        if duration < self.MIN_DURATION_SECONDS:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        dominant_msg = None
        if timeline:
            messages = [
                str(e.get("message", ""))
                for e in timeline.raw_events
                if e.get("reason") == "FailedMount"
            ]
            if messages:
                dominant_msg = max(set(messages), key=messages.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="VOLUME_MOUNT_FAILED",
                    message="Persistent volume mount failed repeatedly",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_MOUNT_RETRY_LOOP",
                    message="Pod continues to retry volume mount without success",
                    role="control_loop",
                ),
                Cause(
                    code="POD_PENDING_OR_RUNNING",
                    message="Pod cannot proceed due to failed volume mount",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Pod repeatedly fails volume mounts",
            "confidence": 0.92,
            "causes": chain,
            "evidence": [
                f"Pod '{pod_name}' experienced >= {self.MIN_CONSECUTIVE_FAILURES} consecutive FailedMount events",
                f"Sustained mount failure duration: {timeline.duration_between(lambda e: 'failedmount' in str(e.get('reason', '')).lower()):.1f}s",
                *(
                    ["Dominant mount failure message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "CSI driver errors or misconfiguration",
                "Node disk or volume unavailable",
                "PVC/PV binding issues preventing mount",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pvc -o wide",
                "kubectl describe pvc",
                "Check PV and node availability",
                "Inspect CSI driver logs on affected node",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": ["Pod repeatedly fails to mount volumes"],
            },
        }
