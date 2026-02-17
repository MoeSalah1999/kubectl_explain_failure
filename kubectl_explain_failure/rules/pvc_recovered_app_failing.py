from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class PVCRecoveredButAppStillFailingRule(FailureRule):
    """
    PVC was Pending → becomes Bound
    Pod transitions to Running
    But CrashLoop / container failures continue.

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

        # Failure continues after scheduling
        failure_detected = any(
            timeline_has_pattern(timeline, pattern)
            for pattern in self.FAILURE_PATTERNS
        )

        if not failure_detected:
            return False

        return True

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
                "CrashLoop or failure events continue post-recovery",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod running but container unstable"
                ],
                f"pvc:{pvc_name}": [
                    "PVC Bound successfully before application failures"
                ],
            },
            "suggested_checks": [
                f"kubectl logs {pod_name}",
                "Inspect application configuration for storage path issues",
                "Validate data integrity inside mounted volume",
                "Check for migration/startup scripts failing post-mount",
            ],
            "blocking": True,
        }
