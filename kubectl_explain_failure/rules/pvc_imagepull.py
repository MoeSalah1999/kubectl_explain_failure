
from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.model import has_event

class PVCThenImagePullFailRule(FailureRule):
    name = "PVC Pending then ImagePullFail"
    category = "Compound"
    priority = 100
    blocks = ["ImagePullBackOff"]
    requires = {
        "objects": ["pvc"],
    }

    def matches(self, pod, events, context) -> bool:
        pvc = context.get("blocking_pvc")
        if not pvc:
            return False
        pvc_pending = pvc.get("status", {}).get("phase") == "Pending"
        return pvc_pending and any(has_event(events, r) for r in ["ImagePullBackOff", "ErrImagePull"])

    def explain(self, pod, events, context):
        pvc = context["blocking_pvc"]
        pvc_name = pvc["metadata"]["name"]
        chain = CausalChain(
            causes=[
                Cause(code="PVC_PENDING", message="PVC is Pending", blocking=True),
                Cause(code="IMAGE_PULL_FAIL", message="Image could not be pulled"),
            ]
        )
        return {
            "root_cause": "Pod blocked by PVC Pending then failed to pull image",
            "confidence": 0.97,
            "causes": chain,
            "evidence": [
                f"PVC {pvc_name} is Pending",
                "ImagePullBackOff or ErrImagePull observed"
            ],
            "object_evidence": {f"pvc:{pvc_name}": ["PVC not Bound"]},
            "suggested_checks": [
                f"kubectl describe pvc {pvc_name}",
                "Check image name and imagePullSecrets",
            ],
            "blocking": True,
        }
