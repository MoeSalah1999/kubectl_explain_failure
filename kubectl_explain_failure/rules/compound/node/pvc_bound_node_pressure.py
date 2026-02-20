from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PVCBoundThenNodePressureRule(FailureRule):
    """
    Pod remains Pending despite PVC being Bound, due to Node DiskPressure.
    → PVC successfully bound
    → Node has DiskPressure
    → Pod cannot be scheduled
    """

    name = "PVCBoundThenNodePressure"
    category = "Compound"
    priority = 50
    blocks = ["FailedScheduling"]

    requires = {
        "objects": ["pvc", "node"],
    }

    supported_phases = {"Pending", "Running"}
    deterministic = True

    def matches(self, pod, events, context) -> bool:
        pvc_objs = context.get("objects", {}).get("pvc", {})
        node_objs = context.get("objects", {}).get("node", {})

        if not pvc_objs or not node_objs:
            return False

        pvc_bound = all(
            p.get("status", {}).get("phase") == "Bound" for p in pvc_objs.values()
        )

        node_pressure = any(
            any(
                cond.get("type") == "DiskPressure" and cond.get("status") == "True"
                for cond in node.get("status", {}).get("conditions", [])
            )
            for node in node_objs.values()
        )

        return pvc_bound and node_pressure

    def explain(self, pod, events, context):
        pvc_objs = context.get("objects", {}).get("pvc", {})
        node_objs = context.get("objects", {}).get("node", {})

        pvc_names = [p.get("metadata", {}).get("name", "<pvc>") for p in pvc_objs.values()]
        node_names = [n.get("metadata", {}).get("name", "<node>") for n in node_objs.values()]

        chain = CausalChain(
            causes=[
                Cause(code="PVC_BOUND", message="PVC successfully bound"),
                Cause(code="NODE_PRESSURE", message="Node has DiskPressure", blocking=True),
            ]
        )

        object_evidence = {}
        for name in pvc_names:
            object_evidence[f"pvc:{name}"] = ["PVC bound successfully"]
        for name in node_names:
            object_evidence[f"node:{name}"] = ["Node has DiskPressure=True"]

        return {
            "root_cause": "Pod scheduling blocked by Node disk pressure despite PVC being bound",
            "confidence": 0.92,
            "blocking": True,
            "causes": chain,
            "object_evidence": object_evidence,
            "suggested_checks": [
                "kubectl describe node <node>",
                "kubectl get pvc",
                "kubectl describe pod <pod>",
            ],
        }