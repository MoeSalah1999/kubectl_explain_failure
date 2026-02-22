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

        for c in pod.get("status", {}).get("containerStatuses", []):
            state = c.get("state", {})
            waiting = state.get("waiting", {})
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