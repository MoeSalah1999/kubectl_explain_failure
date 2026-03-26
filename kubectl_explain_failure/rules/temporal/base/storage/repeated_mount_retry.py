from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class RepeatedMountRetryRule(FailureRule):
    """
    Detects a Pod that stays in a kubelet FailedMount retry loop for a PVC-backed
    volume.

    This is a temporal symptom rule, not the underlying root cause. It uses
    FailedMount retry count and duration, and intentionally coexists with more
    specific mount or attach diagnoses.
    """

    name = "RepeatedMountRetry"
    category = "Temporal"
    priority = 90
    deterministic = False
    blocks = [
        "FailedMount",
        "PVCMountFailed",
    ]
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pvc"],
        "optional_objects": ["pv"],
    }

    MOUNT_FAILURE_MARKERS = (
        "unable to attach or mount volumes",
        "mountvolume.setup failed",
        "mountvolume.setupat failed",
        "failed to mount volume",
    )

    EXCLUSION_MARKERS = (
        "already mounted",
        "successfully mounted",
    )

    MIN_CONSECUTIVE_FAILURES = 3
    MIN_DURATION_SECONDS = 300

    def _occurrences(self, event) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _referenced_pvc_names(self, pod: dict, context: dict) -> list[str]:
        pvc_objects = context.get("objects", {}).get("pvc", {})
        referenced = []

        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim = volume.get("persistentVolumeClaim") or {}
            claim_name = claim.get("claimName")
            if claim_name and claim_name in pvc_objects:
                referenced.append(claim_name)

        return referenced or list(pvc_objects.keys())

    def _is_mount_failure(self, event: dict) -> bool:
        if event.get("reason") != "FailedMount":
            return False

        message = str(event.get("message", "")).lower()
        if any(marker in message for marker in self.EXCLUSION_MARKERS):
            return False

        return any(marker in message for marker in self.MOUNT_FAILURE_MARKERS)

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        if not self._referenced_pvc_names(pod, context):
            return False

        mount_failures = [
            event for event in timeline.raw_events if self._is_mount_failure(event)
        ]
        failure_count = sum(self._occurrences(event) for event in mount_failures)

        if failure_count < self.MIN_CONSECUTIVE_FAILURES:
            return False

        duration = timeline.duration_between(lambda e: self._is_mount_failure(e))
        if duration < self.MIN_DURATION_SECONDS:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        mount_failures = [
            event for event in timeline.raw_events if self._is_mount_failure(event)
        ]
        failure_count = sum(self._occurrences(event) for event in mount_failures)
        duration = timeline.duration_between(lambda e: self._is_mount_failure(e))

        dominant_msg = None
        if mount_failures:
            messages = [
                str(event.get("message", ""))
                for event in mount_failures
                for _ in range(self._occurrences(event))
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
            "root_cause": "Pod is stuck in repeated volume mount retries",
            "confidence": 0.92,
            "causes": chain,
            "evidence": [
                f"Pod '{pod_name}' accumulated {failure_count} FailedMount attempts",
                f"Sustained mount retry duration: {duration:.1f}s",
                *(
                    ["Dominant mount failure message: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "CSI driver errors or misconfiguration",
                "Node disk or volume unavailable",
                "PVC or PV issue preventing kubelet from completing the mount",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pvc -o wide",
                "kubectl describe pvc",
                "Check PV and node availability",
                "Inspect kubelet and CSI driver logs on the affected node",
            ],
            "blocking": True,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod repeatedly fails to mount a PVC-backed volume"
                ],
            },
        }
