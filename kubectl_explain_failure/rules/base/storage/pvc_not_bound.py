from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PVCNotBoundRule(FailureRule):
    """
    Pod cannot schedule because its PersistentVolumeClaim
    is not yet Bound.
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
                    role="workload_context",
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
            "object_evidence": {f"pvc:{pvc_name}, phase:{phase}": ["PVC not Bound"]},
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
