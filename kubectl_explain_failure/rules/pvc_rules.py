from kubectl_explain_failure.rules.base_rule import FailureRule


class PVCNotBoundRule(FailureRule):
    name = "PVCNotBound"
    priority = 10
    category = "PersistentVolumeClaim"
    phases = ["Pending"]  # Only relevant for Pending pods
    requires = {"context": ["pvc"]}

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
                f"PVC '{pvc.get('metadata', {}).get('name')}' phase is {pvc.get('status', {}).get('phase')}"
            ],
            "object_evidence": {
                f"pvc:{pvc.get('metadata', {}).get('name')}": [
                    "PVC is not in Bound phase"
                ]
            },
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


class PVCMountFailedRule(FailureRule):
    name = "PVCMountFailed"
    priority = 9
    category = "PersistentVolumeClaim"
    phases = ["Pending", "Running"]
    requires = {"context": ["pvc"]}

    def matches(self, pod, events, context):
        # Fires if any event is FailedMount
        return any(e["reason"] == "FailedMount" for e in events)

    def explain(self, pod, events, context):
        pvc = context.get("pvc")
        pvc_name = pvc.get("metadata", {}).get("name") if pvc else "<unknown>"
        return {
            "root_cause": "Pod is blocked by unbound PersistentVolumeClaim (mount failed)",
            "evidence": [f"Volume mount failed for PVC '{pvc_name}'"],
            "object_evidence": {f"pvc:{pvc_name}": ["Volume mount failed"]},
            "likely_causes": ["PVC not bound or PV not available"],
            "suggested_checks": [
                "Check events for FailedMount",
                "Ensure PV exists and is bound",
            ],
            "confidence": 0.9,
        }
