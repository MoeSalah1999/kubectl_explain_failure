from __future__ import annotations

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class LowConfidenceDiagnosisRule(FailureRule):
    """
    Reports when the engine has live failure evidence but no earlier rule was
    specific enough to produce a concrete diagnosis.

    This is an engine-level fallback:
    - it runs after higher-priority rules and inspects engine match state
    - it should only trigger when no prior diagnosis matched
    - it turns "Unknown despite active failures" into an explicit statement
      that the available evidence is too weak or generic for confident attribution
    """

    name = "LowConfidenceDiagnosis"
    category = "Compound"
    priority = 4
    deterministic = False

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    WINDOW_MINUTES = 20
    CACHE_KEY = "_low_confidence_diagnosis_candidate"
    FAILURE_REASONS = {
        "Failed",
        "BackOff",
        "CrashLoopBackOff",
        "FailedMount",
        "FailedScheduling",
        "ImagePullBackOff",
        "ErrImagePull",
        "FailedCreatePodSandBox",
        "FailedCreatePodSandbox",
        "Unhealthy",
    }

    def _failure_events(self, timeline: Timeline) -> list[dict]:
        return [
            event
            for event in timeline.events_within_window(self.WINDOW_MINUTES)
            if str(event.get("reason", "")) in self.FAILURE_REASONS
            or timeline.normalized[timeline.events.index(event)].phase == "Failure"
        ]

    def _generic_waiting_evidence(self, pod: dict) -> list[str]:
        evidence = []
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            waiting = (status.get("state", {}) or {}).get("waiting", {}) or {}
            reason = str(waiting.get("reason", "")).strip()
            if not reason:
                continue
            evidence.append(
                f"Container '{status.get('name', '<container>')}' remains waiting: {reason}"
            )
        return evidence

    def _candidate(self, pod: dict, context: dict):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        engine_state = context.get("_engine_state", {}) or {}
        prior_matches = engine_state.get("matched_rules", []) or []
        if prior_matches:
            return None

        failure_events = self._failure_events(timeline)
        if not failure_events:
            return None

        dominant_event = max(
            failure_events,
            key=lambda event: int(event.get("count", 1) or 1),
        )
        waiting_evidence = self._generic_waiting_evidence(pod)

        return {
            "failure_events": failure_events,
            "dominant_event": dominant_event,
            "waiting_evidence": waiting_evidence,
        }

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, context)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(pod, context)
        if candidate is None:
            raise ValueError("LowConfidenceDiagnosis explain() called without match")

        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        dominant_event = candidate["dominant_event"]
        dominant_reason = str(dominant_event.get("reason", "<unknown>"))
        dominant_message = str(dominant_event.get("message", "")).strip()
        failure_count = len(candidate["failure_events"])

        evidence = [
            f"Recent timeline still contains {failure_count} failure event(s), but no higher-priority diagnosis matched",
            f"Most specific remaining event is {dominant_reason}: {dominant_message}",
        ]
        evidence.extend(candidate["waiting_evidence"][:2])

        chain = CausalChain(
            causes=[
                Cause(
                    code="FAILURE_SIGNALS_PRESENT_WITHOUT_MATCH",
                    message="Pod still emits failure signals, but no specific diagnostic rule matched the current evidence set",
                    role="diagnostic_context",
                ),
                Cause(
                    code="AVAILABLE_EVIDENCE_TOO_GENERIC",
                    message="The remaining evidence is too sparse or generic to support a confident root-cause diagnosis",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="LOW_CONFIDENCE_REPORTED",
                    message="Engine reports low-confidence diagnosis instead of presenting an unjustified root cause",
                    role="diagnostic_symptom",
                ),
            ]
        )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod shows active failure symptoms without enough specific evidence for a confident diagnosis"
            ]
        }

        return {
            "root_cause": "Available evidence is too weak for a confident root-cause diagnosis",
            "confidence": 0.82,
            "blocking": False,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The remaining events are generic symptoms rather than root-cause-specific errors",
                "Important context objects or earlier events are missing from the diagnostic input",
                "The failure pattern is real, but it is not yet covered by a more specific rule",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Re-run diagnostics with the full recent event timeline and related objects",
                "Check container logs, init-container logs, and node events to collect a more specific failure marker",
            ],
        }
