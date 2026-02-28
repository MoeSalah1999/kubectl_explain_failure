from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PVCNotBoundRule(FailureRule):
    """
    Detects Pods that cannot schedule because their PersistentVolumeClaim
    is not yet Bound.

    Signals:
    - PVC exists but its status.phase != "Bound"
    - Pod remains in Pending phase due to unbound PVC
    - Timeline or context indicates PVC is unbound

    Interpretation:
    The Pod cannot be scheduled because the PersistentVolumeClaim it depends
    on has not yet been bound to a PersistentVolume. This may result from
    no matching PV, a failed StorageClass provisioning, or unavailable dynamic
    provisioner. Until the PVC is Bound, the Pod remains in Pending state.

    Scope:
    - Volume/PVC layer
    - Deterministic (object-state based)
    - Acts as a root cause for scheduling and mount failures

    Exclusions:
    - Does not include PVCs that are Bound
    - Does not cover transient scheduling delays unrelated to PVC state
    """

    name = "PVCNotBound"
    category = "PersistentVolumeClaim"
    priority = 22
    phases = ["Pending"]

    requires = {
        "objects": ["pvc"],
    }

    # This is the true root — suppress downstream noise
    blocks = ["FailedScheduling", "FailedMount"]
    deterministic = True

    def matches(self, pod, events, context) -> bool:
        # Engine canonical signal (preferred)
        if context.get("pvc_unbound"):
            return True

        # Defensive fallback (object graph scan)
        pvc_objects = context.get("objects", {}).get("pvc", {})
        for pvc in pvc_objects.values():
            phase = pvc.get("status", {}).get("phase")
            if phase != "Bound":
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        pvc = context.get("blocking_pvc")

        if not pvc:
            pvc = next(
                iter(context.get("objects", {}).get("pvc", {}).values()),
                {},
            )

        pvc_name = pvc.get("metadata", {}).get("name", "<unknown>")
        phase = pvc.get("status", {}).get("phase", "<unknown>")

        root_cause_msg = "PersistentVolumeClaim not bound"

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_PRESENT",
                    message=f"PVC '{pvc_name}' attached to Pod",
                    role="volume_context",
                ),
                Cause(
                    code="PVC_NOT_BOUND",
                    message=f"PVC '{pvc_name}' phase is '{phase}'",
                    blocking=True,
                    role="volume_root",
                ),
                Cause(
                    code="SCHEDULING_BLOCKED",
                    message="Pod cannot be scheduled until PVC is Bound",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": root_cause_msg,
            "confidence": 0.97,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"PVC {pvc_name} phase: {phase}",
                "PVC not in Bound state",
            ],
            "object_evidence": {
                f"pvc:{pvc_name}, phase:{phase}": ["PVC not Bound"]
            },
            "likely_causes": [
                "No PersistentVolume matches the PVC",
                "StorageClass provisioning failed",
                "Dynamic provisioner unavailable",
            ],
            "suggested_checks": [
                f"kubectl describe pvc {pvc_name}",
                "kubectl get pv",
                "kubectl get storageclass",
            ],
        }
