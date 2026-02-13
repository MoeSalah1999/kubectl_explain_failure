from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class StorageClassProvisionerMissingRule(FailureRule):
    """
    Detects PVC stuck Pending due to missing or uninstalled provisioner.
    PVC.phase=Pending AND StorageClass.provisioner absent or invalid.
    """

    name = "StorageClassProvisionerMissing"
    category = "PersistentVolumeClaim"
    priority = 23

    requires = {
        "objects": ["pvc", "storageclass"],
    }

    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        pvc_objs = context.get("objects", {}).get("pvc", {})
        sc_objs = context.get("objects", {}).get("storageclass", {})

        if not pvc_objs:
            return False

        # Find unbound PVC
        for pvc in pvc_objs.values():
            phase = pvc.get("status", {}).get("phase")
            if phase != "Pending":
                continue

            sc_name = pvc.get("spec", {}).get("storageClassName")
            if not sc_name:
                continue

            sc = sc_objs.get(sc_name)
            if not sc:
                return True

            provisioner = sc.get("provisioner")
            if not provisioner:
                return True

        return False

    def explain(self, pod, events, context):
        pvc_objs = context.get("objects", {}).get("pvc", {})
        sc_objs = context.get("objects", {}).get("storageclass", {})

        affected = []
        for pvc_name, pvc in pvc_objs.items():
            if pvc.get("status", {}).get("phase") != "Pending":
                continue

            sc_name = pvc.get("spec", {}).get("storageClassName")
            sc = sc_objs.get(sc_name)
            if not sc or not sc.get("provisioner"):
                affected.append(pvc_name)

        chain = CausalChain(
            causes=[
                Cause(
                    code="STORAGECLASS_PROVISIONER_MISSING",
                    message=f"StorageClass provisioner missing for PVC(s): {', '.join(affected)}",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "PVC cannot be provisioned due to missing StorageClass provisioner",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "PVC.status.phase=Pending",
                "StorageClass.provisioner missing or not installed",
            ],
            "object_evidence": {
                f"pvc:{name}": ["Provisioner missing for referenced StorageClass"]
                for name in affected
            },
            "likely_causes": [
                "CSI driver not installed",
                "Incorrect provisioner name in StorageClass",
                "Cluster missing storage plugin",
            ],
            "suggested_checks": [
                "kubectl get storageclass -o yaml",
                "kubectl get pods -n kube-system | grep csi",
            ],
        }
