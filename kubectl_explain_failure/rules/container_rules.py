from kubectl_explain_failure.model import get_pod_name
from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class OOMKilledRule(FailureRule):
    name = "OOMKilled"
    category = "Container"
    priority = 16

    requires = {
        "pod": True,
    }

    phases = ["Running", "Failed"]
    container_states = ["terminated"]

    def matches(self, pod, events, context) -> bool:
        for cs in pod.get("status", {}).get("containerStatuses", []):
            last_state = cs.get("lastState", {})
            terminated = last_state.get("terminated")
            if terminated and terminated.get("reason") == "OOMKilled":
                return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="OOM_KILLED",
                    message="Container terminated due to out-of-memory",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Container was terminated due to out-of-memory",
            "confidence": 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Container lastState.terminated.reason = OOMKilled"
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["Container terminated with OOMKilled"]
            },
            "likely_causes": [
                "Memory limit too low",
                "Memory spike during workload",
                "Memory leak in application",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                f"kubectl logs {pod_name} -n {namespace}",
                "Review container memory limits and usage",
            ],
        }


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


class RepeatedCrashLoopRule(FailureRule):
    name = "RepeatedCrashLoop"
    category = "Container"
    priority = 14
    requires = {
        "pod": True,
    }
    phases = ["Running"]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False
        return timeline_has_pattern(timeline, r"BackOff")

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="REPEATED_CRASH_LOOP",
                    message="Container repeatedly crashing over time",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Container is repeatedly crashing",
            "confidence": 0.9,
            "blocking": True,
            "causes": chain,
            "evidence": ["BackOff pattern detected in event timeline"],
            "object_evidence": {
                f"pod:{pod_name}": ["Repeated crash pattern detected"]
            },
            "likely_causes": [
                "Application instability",
                "Invalid container configuration",
                "Dependency failures",
            ],
            "suggested_checks": [
                f"kubectl logs {pod_name} -n {namespace}",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }


class StartupProbeFailureRule(FailureRule):
    """
    Detects containers failing startupProbe before readiness/liveness.
    Triggered by:
      - container waiting/terminated
      - event message contains 'startup probe'
    """

    name = "StartupProbeFailure"
    category = "Container"
    priority = 17
    blocks = ["CrashLoopBackOff", "RepeatedCrashLoop"]
    requires = {
        "pod": True,
    }

    phases = ["Running", "Pending"]

    container_states = ["terminated", "waiting"]

    def matches(self, pod, events, context) -> bool:
        for e in events or []:
            msg = (e.get("message") or "").lower()
            if "startup probe" in msg and "fail" in msg:
                return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="STARTUP_PROBE_FAILED",
                    message="Container startupProbe failed",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Container failed startupProbe checks",
            "confidence": 0.93,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Event message indicates startupProbe failure",
                f"Pod: {pod_name}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": ["startupProbe failure detected"]
            },
            "likely_causes": [
                "Application not ready during startup",
                "Incorrect probe configuration",
                "Slow initialization time",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "Review startupProbe configuration in Pod spec",
            ],
        }
