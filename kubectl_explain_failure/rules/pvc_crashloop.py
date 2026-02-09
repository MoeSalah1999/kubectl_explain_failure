from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class PVCThenCrashLoopRule(FailureRule):
    name = "PVCThenCrashLoop"
    category = "Compound"
    priority = 45
    dependencies = ["PVCNotBound", "CrashLoopBackOff"]
    blocks = ["CrashLoopBackOff"]

    requires = {
        "objects": ["pvc"],
    }

    def matches(self, pod, events, context) -> bool:
        return True  # dependency-gated

    def explain(self, pod, events, context):
        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_BLOCKING",
                    message="PersistentVolumeClaim blocked pod startup",
                    blocking=True,
                ),
                Cause(
                    code="CONTAINER_RESTARTS",
                    message="Containers repeatedly restarted while waiting for volume",
                ),
            ]
        )

        return {
            "root_cause": "CrashLoopBackOff caused by missing volume",
            "confidence": 0.95,
            "causes": chain,
        }
