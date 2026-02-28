from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PVReleasedOrFailedRule(FailureRule):
    """
    Detects PersistentVolumes that are in Released or Failed state, making
    their associated PVCs unusable even if they appear Bound.

    Signals:
    - PV.status.phase == "Released" or "Failed"
    - PV objects present in cluster

    Interpretation:
    The PersistentVolume backing the claim is unusable. Any Pod relying on
    this PV may fail to start or mount the volume, leading to workload
    disruption.

    Scope:
    - PersistentVolume layer
    - Deterministic (object-state based)
    - Acts as a compound check for PV lifecycle anomalies

    Exclusions:
    - Does not include PVC misconfiguration unrelated to PV state
    - Does not include transient volume provisioning delays
    """

    name = "PVReleasedOrFailed"
    category = "Compound"
    priority = 60

    requires = {
        "objects": ["pv"],
    }

    def matches(self, pod, events, context) -> bool:
        pv_objs = context.get("objects", {}).get("pv", {})
        if not pv_objs:
            return False

        for pv in pv_objs.values():
            phase = pv.get("status", {}).get("phase")
            if phase in ("Released", "Failed"):
                return True

        return False

    def explain(self, pod, events, context):
        pv_objs = context.get("objects", {}).get("pv", {})
        affected = [
            name
            for name, pv in pv_objs.items()
            if pv.get("status", {}).get("phase") in ("Released", "Failed")
        ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_BOUND_TO_PV",
                    message=f"PVCs reference PV(s): {', '.join(affected)}",
                    role="volume_context",
                ),
                Cause(
                    code="PV_RELEASED_OR_FAILED",
                    message=f"PersistentVolume(s) unusable: {', '.join(affected)}",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_VOLUME_UNAVAILABLE",
                    message="Pods cannot access volume(s) due to PV state",
                    role="volume_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "PersistentVolume backing claim is Released or Failed",
            "confidence": 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "PV.status.phase in [Released, Failed]",
                f"PV objects: {', '.join(affected)}",
            ],
            "object_evidence": {
                f"pv:{name}": ["PV in Released/Failed state"] for name in affected
            },
            "likely_causes": [
                "PVC was deleted before PV reclaim",
                "Storage backend failure",
                "Manual PV lifecycle intervention",
            ],
            "suggested_checks": [f"kubectl describe pv {name}" for name in affected],
        }
