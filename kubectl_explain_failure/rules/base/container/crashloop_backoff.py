from kubectl_explain_failure.model import get_pod_name
from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern



class CrashLoopBackOffRule(FailureRule):
    name = "CrashLoopBackOff"
    category = "Container"
    priority = 15
    blocks = ["RepeatedCrashLoop"]
    requires = {
        "pod": True,
    }
    phases = ["Running", "Pending"]

    def matches(self, pod, events, context) -> bool:
        return any(e.get("reason") == "BackOff" for e in events or [])

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        backoff_events = [
            f"{e.get('reason')} - {e.get('message', '')}"
            for e in events or []
            if e.get("reason") == "BackOff"
        ]
        evidence = list(backoff_events)

        # state-based evidence
        for cs in pod.get("status", {}).get("containerStatuses", []):
            state = cs.get("state", {})
            waiting = state.get("waiting")
            if waiting and waiting.get("reason") == "CrashLoopBackOff":
                evidence.append(
                    f"Container '{cs.get('name')}' waiting: CrashLoopBackOff"
                )

        if not evidence:
            evidence = ["BackOff event detected"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="CRASH_LOOP_BACKOFF",
                    message="Container repeatedly crashing and restarting",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Container is crashing (CrashLoopBackOff)",
            "confidence": 0.92,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": ["CrashLoopBackOff condition detected"]
            },
            "likely_causes": [
                "Application crash on startup",
                "Invalid container command or entrypoint",
                "Configuration error",
                "Dependency service unavailable",
            ],
            "suggested_checks": [
                f"kubectl logs {pod_name} -n {namespace}",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }
