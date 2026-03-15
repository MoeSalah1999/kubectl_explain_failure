from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CSIPluginNotRegisteredRule(FailureRule):
    """
    Detects pods failing due to missing CSI driver on a node.

    Signals:
    - StorageClass exists
    - Provisioner is available
    - Node missing the CSI plugin/driver

    Interpretation:
    PVCs cannot be provisioned or attached because the node
    does not have the required CSI driver installed. This
    is a deterministic scheduling/storage failure.

    Scope:
    - Node-level failure
    - Deterministic
    """

    name = "CSIPluginNotRegistered"
    category = "Storage"
    priority = 50
    deterministic = True
    blocks = []
    requires = {
        "objects": ["storageclass", "node"],
    }

    def matches(self, pod, events, context) -> bool:
        objects = context.get("objects", {})
        storageclasses = objects.get("storageclass", {})
        nodes = objects.get("node", {})

        if not storageclasses or not nodes:
            return False

        # Check if any PVC in the pod uses a StorageClass with a provisioner
        for pvc in context.get("objects", {}).get("pvc", {}).values():
            sc_name = pvc.get("spec", {}).get("storageClassName")
            if not sc_name:
                continue
            sc = storageclasses.get(sc_name)
            if not sc:
                continue
            provisioner = sc.get("provisioner")
            if not provisioner:
                continue

            # Check if all nodes are missing this CSI driver
            missing_driver = all(
                provisioner not in node.get("status", {}).get("drivers", [])
                for node in nodes.values()
            )
            if missing_driver:
                return True

        return False

    def explain(self, pod, events, context):
        pvc_names = list(context.get("objects", {}).get("pvc", {}).keys())
        node_names = list(context.get("objects", {}).get("node", {}).keys())
        sc_names = list(context.get("objects", {}).get("storageclass", {}).keys())

        chain = CausalChain(
            causes=[
                Cause(
                    code="STORAGECLASS_PRESENT",
                    message="StorageClass exists with a provisioner",
                    role="storage_context",
                ),
                Cause(
                    code="NODE_MISSING_CSI_DRIVER",
                    message="All nodes are missing the required CSI driver",
                    role="node_root",
                    blocking=True,
                ),
                Cause(
                    code="PVC_PROVISIONING_BLOCKED",
                    message="PVCs cannot be provisioned due to missing CSI driver",
                    role="pvc_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "PVCs cannot be scheduled due to missing CSI driver on nodes",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                f"StorageClasses: {', '.join(sc_names)}",
                f"Nodes: {', '.join(node_names)}",
                f"PVCs: {', '.join(pvc_names)}",
            ],
            "object_evidence": {
                f"pvc:{name}": ["Requires CSI driver not found on any node"]
                for name in pvc_names
            },
            "likely_causes": [
                "Node(s) missing CSI driver installation",
                "Cluster misconfiguration of storage plugins",
                "PVCs requesting StorageClass that cannot be satisfied",
            ],
            "suggested_checks": [
                "kubectl get nodes -o json | jq '.items[].status.drivers'",
                "kubectl describe storageclass <name>",
                "kubectl describe pvc <name>",
            ],
        }
