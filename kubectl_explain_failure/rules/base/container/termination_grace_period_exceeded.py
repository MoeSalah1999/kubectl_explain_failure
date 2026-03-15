from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class TerminationGracePeriodExceededRule(FailureRule):
    """
    Detects containers repeatedly stuck in Terminating state due to exceeding
    the terminationGracePeriodSeconds, resulting in SIGKILL after timeout.

    Signals:
    - Container.status.state.terminating present repeatedly
    - Duration between container termination start and end exceeds grace timeout

    Interpretation:
    The container failed to terminate gracefully within the configured
    terminationGracePeriodSeconds and was forcibly killed. This may indicate
    application shutdown hooks not completing or stuck processes.

    Scope:
    - Runtime / container-level
    - Deterministic if based on event timeline
    """

    name = "TerminationGracePeriodExceeded"
    category = "Container"
    priority = 55
    deterministic = True
    blocks = []
    requires = {
        "objects": ["pod"],
    }

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        # Look for repeated Terminating events in timeline
        terminating_events = [
            e for e in events if "terminating" in (e.get("message") or "").lower()
        ]

        # Require at least 2 events to consider it repeated
        if len(terminating_events) < 2:
            return False

        # Optional: check duration exceeds grace period from pod spec
        containers = pod.get("spec", {}).get("containers", [])
        for c in containers:
            grace = c.get("terminationGracePeriodSeconds", 30)
            # Check last vs first event timestamps
            if len(terminating_events) >= 2:
                first_ts = terminating_events[0].get(
                    "lastTimestamp"
                ) or terminating_events[0].get("eventTime")
                last_ts = terminating_events[-1].get(
                    "lastTimestamp"
                ) or terminating_events[-1].get("eventTime")
                if first_ts and last_ts:
                    from datetime import datetime

                    try:
                        start = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
                        end = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
                        if (end - start).total_seconds() >= grace:
                            return True
                    except Exception:
                        pass

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        chain = CausalChain(
            causes=[
                Cause(
                    code="CONTAINER_RUNNING",
                    message="Container was running normally",
                    role="container_context",
                ),
                Cause(
                    code="TERMINATION_GRACE_EXCEEDED",
                    message="Container failed to terminate within terminationGracePeriodSeconds",
                    role="container_root",
                    blocking=True,
                ),
                Cause(
                    code="SIGKILL_ENFORCED",
                    message="Kubelet forcibly killed the container after grace timeout",
                    role="runtime_symptom",
                ),
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Container repeatedly stuck Terminating beyond grace period",
            "confidence": 0.95,
            "causes": chain,
            "blocking": True,
            "evidence": [
                "Pod.status.containerStatuses indicate repeated terminating events",
                "Pod.spec.containers terminationGracePeriodSeconds checked",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Container stuck Terminating beyond grace period"]
            },
            "likely_causes": [
                "Application shutdown hooks not completing",
                "Stuck background processes preventing termination",
                "Pod termination deadline shorter than actual shutdown time",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Check container terminationGracePeriodSeconds in Pod spec",
                "Inspect application logs for shutdown hooks or stuck processes",
            ],
        }
