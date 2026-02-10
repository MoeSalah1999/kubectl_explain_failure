
from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.model import has_event

class CrashLoopWithConfigOrSecretRule(FailureRule):
    name = "CrashLoopWithConfigOrSecret"
    category = "Compound"
    priority = 46
    blocks = ["CrashLoopBackOff"]
    requires = {
        "objects": ["pvc", "configmap"],
    }

    def matches(self, pod, events, context) -> bool:
        config_events = any(has_event(events, r) for r in ["CreateContainerConfigError", "ImagePullBackOff"])
        crashloop = any(has_event(events, "BackOff"))
        return config_events and crashloop

    def explain(self, pod, events, context):
        chain = CausalChain(
            causes=[
                Cause(code="CONFIG_SECRET_FAIL", message="ConfigMap or Secret missing"),
                Cause(code="CRASHLOOP", message="Containers repeatedly restarted"),
            ]
        )
        return {
            "root_cause": "CrashLoopBackOff due to missing ConfigMap/Secret",
            "confidence": 0.96,
            "causes": chain,
            "evidence": ["BackOff event", "ConfigMap/Secret missing events"],
            "suggested_checks": [
                "kubectl get configmap",
                "kubectl get secret",
                "kubectl describe pod <name>",
            ],
            "blocking": True,
        }
