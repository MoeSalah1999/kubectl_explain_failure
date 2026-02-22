from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern, Timeline


class PVCBoundThenCrashLoopRule(FailureRule):
    """
    PVC must have transitioned from unbound → bound
    App is still failing (CrashLoopBackOff or pod not ready)
    → Indicates application-level failure after storage recovery.
    """

    name = "PVCBoundThenCrashLoop"
    category = "Compound"
    priority = 70
    blocks = ["PVCNotBound", "CrashLoopBackOff"]
    phases = ["Running"]
    requires = {"objects": ["pvc"], "context": ["timeline"]}

    def matches(self, pod, events, context) -> bool:
        pvc_objs = context.get("objects", {}).get("pvc", {})
        timeline_obj: Timeline = context.get("timeline")

        if not pvc_objs or not timeline_obj:
            return False

        # --- Check PVCs have transitioned from Pending → Bound ---
        pvc_transitions = []
        for pvc_name, pvc in pvc_objs.items():
            # Get events for this PVC within last N minutes
            recent_events = timeline_obj.events_within_window(
                minutes=60,  # for example
                reason="PersistentVolumeClaimBound"
            )
            # Only consider PVCs that actually transitioned from Pending -> Bound
            pattern = [
                {"reason": "PersistentVolumeClaimPending"},
                {"reason": "PersistentVolumeClaimBound"}
            ]
            if timeline_has_pattern(recent_events, pattern):
                pvc_transitions.append(pvc_name)

        if not pvc_transitions:
            return False

        # --- Check if any container is still failing ---
        for c in pod.get("status", {}).get("containerStatuses", []):
            state = c.get("state", {})
            waiting = state.get("waiting", {})
            running = state.get("running", None)

            # Pod is failing if in CrashLoopBackOff or not ready
            if waiting.get("reason") == "CrashLoopBackOff" or not c.get("ready", True):
                return True

        return False

    def explain(self, pod, events, context):
        pvc_objs = context.get("objects", {}).get("pvc", {})
        pvc_names = [p["metadata"]["name"] for p in pvc_objs.values()]

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_BOUND",
                    message=f"PersistentVolumeClaim(s) Bound after Pending: {', '.join(pvc_names)}"
                ),
                Cause(code="CRASH_LOOP", message="Container repeatedly crashing", blocking=True),
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