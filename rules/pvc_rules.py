from rules.base_rule import FailureRule
from model import get_pod_name, get_pod_phase, has_event

class PVCNotBoundRule(FailureRule):
    name = "PVCNotBound"
    priority = 10

    def matches(self, pod, events, context):
        pvc = context.get("pvc")
        if not pvc:
            return False
        return pvc.get("status", {}).get("phase") != "Bound"

    def explain(self, pod, events, context):
        pvc = context["pvc"]
        return {
            "root_cause": "Pod is blocked by unbound PersistentVolumeClaim",
            "evidence": [
                f"PVC {pvc.get('metadata', {}).get('name')} phase is {pvc.get('status', {}).get('phase')}"
            ],
            "likely_causes": [
                "No matching PersistentVolume available",
                "StorageClass provisioning failed",
            ],
            "suggested_checks": [
                "kubectl get pvc",
                "kubectl describe pvc <name>",
                "kubectl get pv",
            ],
            "confidence": 0.95,
        }
