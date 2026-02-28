from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class StorageClassProvisionerMissingRule(FailureRule):
    """
    Detects PersistentVolumeClaims stuck in Pending state due to a missing
    or uninstalled StorageClass provisioner.

    Signals:
    - PVC.status.phase == "Pending"
    - PVC references a StorageClass whose provisioner is absent or invalid
    - PVC cannot be dynamically provisioned

    Interpretation:
    The PVC cannot be fulfilled because the referenced StorageClass has no
    valid provisioner installed. This prevents volume creation, blocking
    Pods from mounting or starting until the issue is resolved.

    Scope:
    - Volume/PVC layer
    - Deterministic (object-state based)
    - Acts as a root cause for PVC provisioning failures

    Exclusions:
    - Does not include PVCs that are already Bound
    - Does not cover transient delays in PVC provisioning
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
                    code="PVC_REFERENCES_STORAGECLASS",
                    message=f"PVC(s) reference StorageClass: {', '.join(affected)}",
                    role="volume_context",
                ),
                Cause(
                    code="STORAGECLASS_PROVISIONER_MISSING",
                    message=f"Provisioner missing for PVC(s): {', '.join(affected)}",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="PVC_PROVISIONING_BLOCKED",
                    message="PVC(s) cannot be provisioned",
                    role="volume_symptom",
                ),
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
