from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class PVCRecoveredButAppStillFailingRule(FailureRule):
    """
    PVC was Pending → becomes Bound
    Pod transitions to Running
    But CrashLoop / container failures continue within a recent window.
    Root cause shifts from infrastructure to application layer.
    """

    name = "PVCRecoveredButAppStillFailing"
    category = "Compound"
    priority = 62  # Higher than simple PVC + CrashLoop rules
    blocks = [
        "PVCNotBound",
        "PVCProvisioningFailed",
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
    ]

    phases = ["Running", "CrashLoopBackOff"]

    requires = {
        "context": ["timeline"],
        "objects": ["pvc"],
    }

    container_states = ["waiting", "terminated"]

    FAILURE_PATTERNS = [
        "CrashLoopBackOff",
        "BackOff",
        "Error",
        "Failed",
    ]

    # Consider events in last N minutes only
    LOOKBACK_MINUTES = 60

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        pvc_objects = context.get("objects", {}).get("pvc", {})

        if not timeline or not pvc_objects:
            return False

        # PVC currently Bound
        pvc = next(iter(pvc_objects.values()))
        pvc_phase = pvc.get("status", {}).get("phase")
        if pvc_phase != "Bound":
            return False

        # Historical Pending event must exist
        if not timeline_has_pattern(timeline, "Pending"):
            return False

        # Pod scheduled successfully
        if not timeline_has_pattern(timeline, "Scheduled"):
            return False

        # Failure continues either in recent window OR at all if no timestamps
        failure_detected = False
        for pattern in self.FAILURE_PATTERNS:
            if hasattr(timeline, "events_within_window"):
                recent_failures = timeline.events_within_window(
                    minutes=self.LOOKBACK_MINUTES,
                    reason=pattern,
                )
                if recent_failures:
                    failure_detected = True
                    break
            # fallback for legacy events with no timestamp
            if timeline_has_pattern(timeline, pattern):
                failure_detected = True
                break

        return failure_detected

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        pvc_objects = context.get("objects", {}).get("pvc", {})
        pvc = next(iter(pvc_objects.values()))
        pvc_name = pvc.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_RECOVERED",
                    message="PersistentVolumeClaim was successfully bound",
                    role="infrastructure_resolved",
                ),
                Cause(
                    code="POD_RUNNING_AFTER_PVC",
                    message="Pod transitioned to Running after PVC binding",
                    role="scheduler_intermediate",
                ),
                Cause(
                    code="APPLICATION_CRASHLOOP",
                    message="Application continues failing despite storage recovery",
                    blocking=True,
                    role="container_root",
                ),
            ]
        )

        return {
            "root_cause": "Application failure persists after PVC recovery",
            "confidence": 0.93,
            "causes": chain,
            "evidence": [
                "PVC previously Pending but now Bound",
                "Pod successfully scheduled",
                f"CrashLoop or failure events detected within last {self.LOOKBACK_MINUTES} minutes",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Pod running but container unstable"],
                f"pvc:{pvc_name}": ["PVC Bound successfully before application failures"],
            },
            "suggested_checks": [
                f"kubectl logs {pod_name}",
                "Inspect application configuration for storage path issues",
                "Validate data integrity inside mounted volume",
                "Check for migration/startup scripts failing post-mount",
            ],
            "blocking": True,
        }