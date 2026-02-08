from kubectl_explain_failure.rules.base_rule import FailureRule


class PVCNotBoundRule(FailureRule):
    name = "PVCNotBound"
    priority = 10
    category = "PersistentVolumeClaim"
    phases = ["Pending"]  # Only relevant for Pending pods

    # Explicit object dependencies
    requires = {
        "objects": ["pvc"],
        "optional_objects": ["pv", "storageclass"],
    }
    # Hard blockers
    blocks = ["FailedScheduling", "FailedMount"]

    def matches(self, pod, events, context):
        pvcs = context["objects"].get("pvc", {})
        for pvc in pvcs.values():
            phase = pvc.get("status", {}).get("phase")
            if phase and phase != "Bound":
                return True
        return False

    def explain(self, pod, events, context):
        pvcs = context["objects"]["pvc"]
        pvc = next(iter(pvcs.values()))
        pvc_name = pvc["metadata"]["name"]
        phase = pvc.get("status", {}).get("phase")
        return {
            "root_cause": "Pod is blocked by unbound PersistentVolumeClaim",
            "confidence": 0.95,
            "evidence": ["PVC is Pending"],
            "object_evidence": {
                f"pvc:{pvc_name}, pvc phase:{phase}": ["PVC is not Bound"]
            },
            "likely_causes": [
                "No PersistentVolume matches the PVC",
                "StorageClass provisioning failed",
            ],
            "suggested_checks": [
                "kubectl describe pvc <name>",
                "kubectl get pv",
                "kubectl get storageclass",
            ],
        }


class PVCMountFailedRule(FailureRule):
    name = "PVCMountFailed"
    priority = 9
    category = "PersistentVolumeClaim"
    phases = ["Pending", "Running"]
    requires = {
        "objects": ["pvc"],
        "optional_objects": ["pv", "node"],
    }

    # Still blocks scheduler noise
    blocks = ["FailedScheduling"]

    def matches(self, pod, events, context):
        # Fires if any event is FailedMount
        return any(e["reason"] == "FailedMount" for e in events)

    def explain(self, pod, events, context):
        pvc = next(iter(context["objects"]["pvc"].values()))
        pvc_name = pvc["metadata"]["name"]
        return {
            "root_cause": "Volume mount failed for PersistentVolumeClaim",
            "confidence": 0.9,
            "evidence": [f"FailedMount event for PVC '{pvc_name}'"],
            "object_evidence": {f"pvc:{pvc_name}": ["Mount operation failed"]},
            "likely_causes": [
                "PVC is not bound",
                "Node cannot access storage backend",
            ],
            "suggested_checks": [
                "kubectl describe pod <name>",
                "kubectl describe pvc <name>",
                "kubectl describe node <node>",
            ],
        }
