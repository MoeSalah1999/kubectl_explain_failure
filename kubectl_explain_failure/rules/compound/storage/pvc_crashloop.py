from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


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

        pvc_transitions = []
        for pvc_name, pvc in pvcs.items():
            pending_events = [
                e for e in timeline.events_within_window(60, reason="PersistentVolumeClaimPending")
                if e.get("involvedObject", {}).get("name") == pvc_name
            ]
            bound_events = [
                e for e in timeline.events_within_window(60, reason="PersistentVolumeClaimBound")
                if e.get("involvedObject", {}).get("name") == pvc_name
            ]

            if pending_events and bound_events:
                # Use parse_time() to compare timestamps safely
                bound_ts = min(
                    parse_time(e.get("eventTime") or e.get("lastTimestamp") or e.get("firstTimestamp"))
                    for e in bound_events
                )

                crash_events = timeline.events_within_window(60, reason="CrashLoopBackOff")
                for e in crash_events:
                    crash_ts = parse_time(e.get("eventTime") or e.get("lastTimestamp") or e.get("firstTimestamp"))
                    if crash_ts <= bound_ts:
                        pvc_transitions.append(pvc_name)
                        break

        return bool(pvc_transitions)

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