# kubectl_explain_failure/rules/pvc_bound_then_node_pressure.py
from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule

class PVCBoundThenNodePressureRule(FailureRule):
    name = "PVCBoundThenNodePressure"
    category = "Compound"
    priority = 49
    blocks = ["FailedScheduling"]
    requires = {
        "objects": ["pvc", "node"],
    }

    def matches(self, pod, events, context) -> bool:
        pvc = context.get("objects", {}).get("pvc", {})
        node_objs = context.get("objects", {}).get("node", {})
        if not pvc or not node_objs:
            return False
        pvc_bound = all(p.get("status", {}).get("phase") == "Bound" for p in pvc.values())
        node_pressure = any(
            any(cond.get("type") == "DiskPressure" and cond.get("status") == "True"
                for cond in node.get("status", {}).get("conditions", []))
            for node in node_objs.values()
        )
        return pvc_bound and node_pressure

    def explain(self, pod, events, context):
        chain = CausalChain(
            causes=[
                Cause(code="PVC_BOUND", message="PVC successfully bound"),
                Cause(code="NODE_PRESSURE", message="Node has DiskPressure", blocking=True),
            ]
        )
        return {
            "root_cause": "Pod scheduling blocked by Node disk pressure despite PVC being bound",
            "confidence": 0.95,
            "causes": chain,
            "suggested_checks": [
                "kubectl describe node <node>",
                "kubectl get pvc",
                "kubectl describe pod <name>",
            ],
            "blocking": True,
        }
