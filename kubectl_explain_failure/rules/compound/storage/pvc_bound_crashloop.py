from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern, parse_time, Timeline


class PVCBoundThenCrashLoopRule(FailureRule):
    """
    Detects Pods that enter CrashLoopBackOff after their
    PersistentVolumeClaim successfully transitions from Pending
    to Bound, indicating that storage recovery did not resolve
    the application failure.

    Signals:
    - PVC transitioned from PersistentVolumeClaimPending to PersistentVolumeClaimBound
    - Pod is Running
    - Container enters CrashLoopBackOff after PVC Bound event

    Interpretation:
    The PersistentVolumeClaim was previously unbound and has
    successfully bound to a PersistentVolume, restoring storage
    availability. Despite this recovery, the application
    continues to crash. This indicates that the failure is
    application-level and no longer attributable to storage
    binding issues.

    Scope:
    - Volume + execution layers (cross-domain temporal correlation)
    - Deterministic (event sequence ordering)
    - Acts as a compound suppression rule for prior PVCNotBound explanations

    Exclusions:
    - Does not include PVCs that remain Pending
    - Does not include scheduling failures
    - Does not include pre-bind container crashes
    """

    name = "PVCBoundThenCrashLoop"
    category = "Compound"
    priority = 59
    blocks = ["PVCNotBound"]
    phases = ["Running"]
    requires = {"objects": ["pvc"], "context": ["timeline"]}

    def matches(self, pod, events, context) -> bool:
        pvc_objs = context.get("objects", {}).get("pvc", {})
        timeline_obj: Timeline = context.get("timeline")

        if not pvc_objs or not timeline_obj:
            return False

        pvc_transitions = []
        for pvc_name, pvc in pvc_objs.items():
            # Support dict events for testing
            pvc_events = [
                e for e in timeline_obj.events
                if (getattr(e, "involvedObject", {}).get("name") 
                    if hasattr(e, "involvedObject") else e.get("involvedObject", {}).get("name")) == pvc_name
            ]

            pattern = [
                {"reason": "PersistentVolumeClaimPending"},
                {"reason": "PersistentVolumeClaimBound"}
            ]
            if timeline_has_pattern(pvc_events, pattern):
                pvc_transitions.append(pvc_name)

        if not pvc_transitions:
            return False

        # Find first PVC Bound event and first container crash event
        container_crash_event = next(
            (e for e in timeline_obj.events if e.get("reason") == "CrashLoopBackOff"), None
        )

        for pvc_name, pvc in pvc_objs.items():
            pvc_events = [
                e for e in timeline_obj.events
                if (getattr(e, "involvedObject", {}).get("name")
                    if hasattr(e, "involvedObject") else e.get("involvedObject", {}).get("name")) == pvc_name
            ]
            pvc_bound_event = next((e for e in pvc_events if e.get("reason") == "PersistentVolumeClaimBound"), None)

            # Only match if CrashLoopBackOff happened AFTER PVC Bound → app still failing post-recovery
            if container_crash_event and pvc_bound_event:
                crash_ts = parse_time(
                    container_crash_event.get("eventTime")
                    or container_crash_event.get("lastTimestamp")
                    or container_crash_event.get("firstTimestamp")
                )
                bound_ts = parse_time(
                    pvc_bound_event.get("eventTime")
                    or pvc_bound_event.get("lastTimestamp")
                    or pvc_bound_event.get("firstTimestamp")
                )
                if crash_ts > bound_ts:
                    return True

        return False
    def explain(self, pod, events, context):
        pvc_objs = context.get("objects", {}).get("pvc", {})
        pvc_names = [p["metadata"]["name"] for p in pvc_objs.values()]

        chain = CausalChain(
            causes=[
                # Context: storage recovered
                Cause(
                    code="PVC_RECOVERY_CONTEXT",
                    message=f"PersistentVolumeClaim(s) successfully bound after Pending: {', '.join(pvc_names)}",
                    role="volume_context",
                ),
                Cause(
                    code="APPLICATION_RUNTIME_FAILURE",
                    message="Container continues crashing after storage successfully bound",
                    role="execution_root",
                    blocking=True,
                ),
                Cause(
                    code="CRASH_LOOP_BACKOFF",
                    message="Container entered CrashLoopBackOff after PVC recovery",
                    role="container_health_intermediate",
                ),
                Cause(
                    code="POD_RUNNING_UNHEALTHY",
                    message="Pod is Running but application repeatedly crashes",
                    role="workload_symptom",
                ),
            ]
        )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        return {
            "root_cause": "Application failing after storage recovery",
            "confidence": 0.92,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Pod {pod_name} running with PVC(s) that transitioned to Bound and failing containers"
            ],
            "object_evidence": {
                **{f"pvc:{name}": ["Bound PVC after Pending"] for name in pvc_names},
                f"pod:{pod_name}": ["Container in CrashLoopBackOff or not ready after PVC Bound"],
            },
            "suggested_checks": [
                f"kubectl logs {pod_name}",
                f"kubectl describe pod {pod_name}",
                "Investigate application-level logs or storage access issues",
            ],
        }