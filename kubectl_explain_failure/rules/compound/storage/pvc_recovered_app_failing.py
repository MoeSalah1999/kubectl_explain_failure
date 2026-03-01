from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class PVCRecoveredButAppStillFailingRule(FailureRule):
    """
    Detects Pods that continue to experience container failures
    after a previously Pending PersistentVolumeClaim has
    successfully bound and the Pod has transitioned to Running.

    Signals:
    - PersistentVolumeClaim.status.phase is Bound
    - Timeline shows historical PVC Pending state
    - Pod successfully Scheduled and transitioned to Running
    - Recent CrashLoopBackOff / BackOff / Error events observed

    Interpretation:
    The original storage-layer blockage has been resolved.
    The Pod is scheduled and volumes are mounted successfully.
    Ongoing container failures therefore indicate an
    application- or container-level root cause independent
    of the PVC lifecycle.

    Scope:
    - Container health layer (post-infrastructure recovery)
    - Deterministic (timeline + object-state correlation)
    - Acts as a compound suppression rule preventing
    misattribution to historical PVC failures

    Exclusions:
    - Does not include active PVC Pending states
    - Does not include mount failures
    - Does not include scheduling failures
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
                    code="PVC_RECOVERED_CONTEXT",
                    message=f"PersistentVolumeClaim {pvc_name} is now Bound",
                    role="volume_context",
                ),
                Cause(
                    code="APPLICATION_CRASH_LOOP",
                    message="Container repeatedly failing despite successful volume binding",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_UNSTABLE",
                    message="Container cannot maintain stable execution",
                    role="execution_intermediate",
                ),
                Cause(
                    code="POD_NOT_READY",
                    message="Pod remains unstable due to repeated container failures",
                    role="workload_symptom",
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