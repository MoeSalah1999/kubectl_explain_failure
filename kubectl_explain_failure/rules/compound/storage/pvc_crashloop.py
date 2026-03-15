from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class PVCThenCrashLoopRule(FailureRule):
    """
    Detects Pods that enter CrashLoopBackOff following a
    PersistentVolumeClaim transition from Pending to Bound,
    indicating the container began failing while waiting for
    volume availability.

    Signals:
    - PVC transitioned from PersistentVolumeClaimPending to PersistentVolumeClaimBound
    - CrashLoopBackOff events occurred before or during volume binding
    - Pod phase is Running

    Interpretation:
    The PersistentVolumeClaim was unavailable during container
    startup. The container attempted to initialize without
    required storage, leading to repeated restarts. Even though
    the PVC eventually bound, the CrashLoopBackOff originated
    from the earlier volume unavailability.

    Scope:
    - Volume + container health layers
    - Deterministic (event ordering within bounded window)
    - Acts as a compound attribution rule for storage-induced CrashLoops

    Exclusions:
    - Does not include CrashLoops caused purely by application logic
    - Does not include PVCs that never transitioned to Bound
    - Does not include post-recovery execution failures
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

        def _get_ts(event: dict) -> str | None:
            return (
                event.get("eventTime")
                or event.get("lastTimestamp")
                or event.get("firstTimestamp")
            )

        pvc_transitions = []
        for pvc_name, _pvc in pvcs.items():
            pending_events = [
                e
                for e in timeline.events_within_window(
                    60, reason="PersistentVolumeClaimPending"
                )
                if e.get("involvedObject", {}).get("name") == pvc_name
            ]
            bound_events = [
                e
                for e in timeline.events_within_window(
                    60, reason="PersistentVolumeClaimBound"
                )
                if e.get("involvedObject", {}).get("name") == pvc_name
            ]

            if pending_events and bound_events:
                # Use parse_time() to compare timestamps safely
                bound_times = []
                for e in bound_events:
                    ts = _get_ts(e)
                    if ts:
                        bound_times.append(parse_time(ts))
                if not bound_times:
                    continue
                bound_ts = min(bound_times)

                crash_events = timeline.events_within_window(
                    60, reason="CrashLoopBackOff"
                )
                for e in crash_events:
                    ts = _get_ts(e)
                    if not ts:
                        continue
                    crash_ts = parse_time(ts)
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
                    code="PVC_UNAVAILABLE_AT_STARTUP",
                    message=f"PersistentVolumeClaim(s) were Pending during container startup: {', '.join(pvc_names)}",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_RESTARTS",
                    message="Container restarted repeatedly while waiting for required volume",
                    role="container_health_intermediate",
                ),
                Cause(
                    code="CRASH_LOOP_BACKOFF",
                    message="Pod entered CrashLoopBackOff due to earlier volume unavailability",
                    role="workload_symptom",
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
                f"pod:{pod_name}": [
                    "Container in CrashLoopBackOff or not ready after PVC Bound"
                ],
            },
            "suggested_checks": [
                f"kubectl describe pvc {', '.join(pvc_names)}",
                f"kubectl logs {pod_name}",
                "Verify application logs and volume access permissions",
            ],
            "blocking": True,
        }
