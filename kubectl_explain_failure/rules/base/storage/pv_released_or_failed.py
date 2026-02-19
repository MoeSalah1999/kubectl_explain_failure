from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PVReleasedOrFailedRule(FailureRule):
    """
    Detects PersistentVolumes that are in Released or Failed state.
    PVC may still appear Bound but backing PV is unusable.
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
                    code="PV_RELEASED_OR_FAILED",
                    message=f"PersistentVolume(s) unusable: {', '.join(affected)}",
                    blocking=True,
                )
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
