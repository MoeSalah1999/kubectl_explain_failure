from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CrashLoopBackOffRule(FailureRule):
    """
    Detects Pods entering CrashLoopBackOff due to containers repeatedly crashing.

    Signals:
      - Timeline contains repeated 'BackOff' events
      - Container state.waiting.reason == "CrashLoopBackOff"

    Interpretation:
      The container process exits repeatedly, triggering the Kubelet to
      apply exponential restart backoff, preventing the Pod from running normally.

    Scope:
      - Container runtime / Kubelet phase
      - Phases: Running, Pending
      - Deterministic (event & state-based)
      - Blocks downstream RepeatedCrashLoop failures

    Exclusions:
      - Does not include ImagePullBackOff errors
      - Does not include PodSecurity or admission failures
    """
    name = "CrashLoopBackOff"
    category = "Container"
    priority = 15
    blocks = ["RepeatedCrashLoop"]
    requires = {
        "pod": True,
        "context": ["timeline"],
    }
    deterministic = True
    phases = ["Running", "Pending"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # At least one BackOff event required
        return timeline.repeated("BackOff", threshold=1)

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        timeline = context.get("timeline")
        raw_events = timeline.raw_events if timeline else (events or [])

        backoff_events = [
            f"{e.get('reason')} - {e.get('message', '')}"
            for e in raw_events
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
                    code="CONTAINER_CRASHING",
                    message="Container process exits repeatedly",
                    role="workload_root",
                    blocking=True,
                ),
                Cause(
                    code="CRASH_LOOP_BACKOFF",
                    message="Kubelet enters exponential restart backoff",
                    role="runtime_symptom",
                ),
                Cause(
                    code="POD_UNABLE_TO_RUN",
                    message="Pod cannot reach Running state due to container crashes",
                    role="workload_symptom",
                ),
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
