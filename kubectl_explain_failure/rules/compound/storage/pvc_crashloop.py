from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern, Timeline


class PVCThenCrashLoopRule(FailureRule):
    """
    PVC Pending → Bound
    Pod still failing (CrashLoopBackOff or container not ready)
    → Indicates CrashLoopBackOff caused by missing or delayed volume
    """

    name = "PVCThenCrashLoop"
    category = "Compound"
    priority = 61
    blocks = ["CrashLoopBackOff"]

    requires = {
        "objects": ["pvc"],
        "context": ["timeline"],
    }

    phases = ["Running"]

    def matches(self, pod, events, context) -> bool:
        objects = context.get("objects", {})
        pvcs = objects.get("pvc", {})
        if not pvcs:
            return False

        timeline: Timeline = context.get("timeline")
        if not timeline:
            return False

        # Check for any PVC that transitioned Pending → Bound
        pvc_transitions = []
        for pvc_name, pvc in pvcs.items():
            pvc_events = [
                e for e in timeline.events
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

        # Find first PVC Pending and Bound events
        container_crash_event = next(
            (e for e in timeline.events if e.get("reason") == "CrashLoopBackOff"), None
        )

        # Only match if CrashLoopBackOff happened BEFORE PVC Bound → missing/delayed volume
        for pvc_name, pvc in pvcs.items():
            pvc_events = [
                e for e in timeline.events
                if (getattr(e, "involvedObject", {}).get("name")
                    if hasattr(e, "involvedObject") else e.get("involvedObject", {}).get("name")) == pvc_name
            ]
            pvc_bound_event = next((e for e in pvc_events if e.get("reason") == "PersistentVolumeClaimBound"), None)

            if container_crash_event and pvc_bound_event and container_crash_event["timestamp"] <= pvc_bound_event["timestamp"]:
                return True

        return False

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        pvc_objs = objects.get("pvc", {})
        pvc_names = [p["metadata"]["name"] for p in pvc_objs.values()]
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_BLOCKING",
                    message=f"PersistentVolumeClaim(s) Bound after Pending: {', '.join(pvc_names)}",
                    blocking=True,
                    role="storage_root",
                ),
                Cause(
                    code="CONTAINER_RESTARTS",
                    message="Containers repeatedly restarted while waiting for volume",
                    blocking=True,
                    role="application_failure",
                ),
            ]
        )

        return {
            "root_cause": "CrashLoopBackOff caused by missing or delayed volume",
            "confidence": 0.95,
            "causes": chain,
            "evidence": [
                f"Pod {pod_name} running with PVC(s) that transitioned from Pending to Bound and failing containers"
            ],
            "object_evidence": {
                **{f"pvc:{name}": ["Bound PVC after Pending"] for name in pvc_names},
                f"pod:{pod_name}": ["Container in CrashLoopBackOff or not ready after PVC Bound"],
            },
            "suggested_checks": [
                f"kubectl describe pvc {', '.join(pvc_names)}",
                f"kubectl logs {pod_name}",
                "Verify application logs and volume access permissions",
            ],
            "blocking": True,
        }