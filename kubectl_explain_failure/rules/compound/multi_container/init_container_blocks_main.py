from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class InitContainerBlocksMainRule(FailureRule):
    """
    Detects Pods whose main containers never start because an init
    container has failed, blocking the initialization sequence.

    Signals:
    - Pod.status.initContainerStatuses contains a failed state
    - Init container reason in [Error, CrashLoopBackOff,
    ImagePullBackOff, CreateContainerConfigError]
    - Main containers not yet started

    Interpretation:
    An init container failed during the initialization phase,
    preventing the kubelet from starting the main application
    containers. Because init containers must complete successfully
    before normal containers start, the Pod cannot progress to
    Running state.

    Scope:
    - Pod + container initialization layer
    - Deterministic (object-state based)
    - Acts as a compound guard to suppress container-level
    crash and probe rules when init failure is the true cause

    Exclusions:
    - Does not include failures occurring after main containers start
    - Does not include controller-level rollout failures
    """

    name = "InitContainerBlocksMain"
    category = "Compound"
    priority = 70  # Higher than container crash rules

    blocks = [
        "CrashLoopBackOff",
        "RepeatedCrashLoop",
        "OOMKilled",
        "ReadinessProbeFailure",
        "StartupProbeFailure",
        "RepeatedProbeFailureEscalation",
        "MultiContainerPartialFailure",
    ]

    phases = ["Pending", "Init", "CrashLoopBackOff"]

    requires = {
        "pod": True,
    }

    FAILURE_REASONS = {
        "Error",
        "CrashLoopBackOff",
        "ImagePullBackOff",
        "CreateContainerConfigError",
    }
    RETRY_ESCALATION_WINDOW_MINUTES = 20
    RETRY_ESCALATION_MIN_OCCURRENCES = 4
    RETRY_ESCALATION_MIN_RESTART_COUNT = 3
    RETRY_ESCALATION_MIN_DURATION_SECONDS = 300

    def _blocked_main_containers(self, pod: dict) -> bool:
        spec_containers = pod.get("spec", {}).get("containers", []) or []
        if not spec_containers:
            return False

        statuses = pod.get("status", {}).get("containerStatuses", []) or []
        statuses_by_name = {
            str(status.get("name", "")): status
            for status in statuses
            if status.get("name")
        }

        for container in spec_containers:
            name = str(container.get("name", ""))
            if not name:
                continue

            status = statuses_by_name.get(name, {})
            state = status.get("state", {}) or {}
            waiting = state.get("waiting", {}) or {}
            waiting_reason = str(waiting.get("reason", "") or "PodInitializing")

            if state.get("running") or state.get("terminated"):
                return False
            if int(status.get("restartCount", 0) or 0) > 0:
                return False
            if waiting_reason not in {"PodInitializing", "ContainerCreating"}:
                return False

        return True

    def _retry_escalation_present(self, pod: dict, context: dict) -> bool:
        timeline = context.get("timeline")
        if not timeline or not self._blocked_main_containers(pod):
            return False

        init_statuses = pod.get("status", {}).get("initContainerStatuses", []) or []
        failing_names = []
        for status in init_statuses:
            state = status.get("state", {}) or {}
            waiting = state.get("waiting", {}) or {}
            if waiting.get("reason") != "CrashLoopBackOff":
                continue
            if (
                int(status.get("restartCount", 0) or 0)
                < self.RETRY_ESCALATION_MIN_RESTART_COUNT
            ):
                continue
            name = str(status.get("name", ""))
            if name:
                failing_names.append(name)

        if not failing_names:
            return False

        occurrence_times = []
        for event in timeline.events_within_window(
            self.RETRY_ESCALATION_WINDOW_MINUTES
        ):
            if str(event.get("reason", "")) != "BackOff":
                continue
            message = str(event.get("message", "")).lower()
            if not (
                any(name.lower() in message for name in failing_names)
                or "failed init container" in message
                or len(failing_names) == 1
            ):
                continue

            count = event.get("count", 1)
            try:
                count_value = max(int(count), 1)
            except Exception:
                count_value = 1

            start = (
                event.get("firstTimestamp")
                or event.get("eventTime")
                or event.get("lastTimestamp")
            )
            end = (
                event.get("lastTimestamp")
                or event.get("eventTime")
                or event.get("firstTimestamp")
            )
            if not start and not end:
                continue

            from kubectl_explain_failure.timeline import parse_time

            try:
                first_ts = parse_time(start) if start else None
                last_ts = parse_time(end) if end else None
            except Exception:
                continue

            anchor = last_ts or first_ts
            if anchor is None:
                continue

            if (
                count_value <= 1
                or first_ts is None
                or last_ts is None
                or last_ts <= first_ts
            ):
                occurrence_times.extend([anchor for _ in range(count_value)])
                continue

            step = (last_ts - first_ts) / (count_value - 1)
            occurrence_times.extend(
                first_ts + (step * index) for index in range(count_value)
            )

        occurrence_times = sorted(occurrence_times)
        if len(occurrence_times) < self.RETRY_ESCALATION_MIN_OCCURRENCES:
            return False
        if len(occurrence_times) < 2:
            return False

        observed_duration_seconds = (
            occurrence_times[-1] - occurrence_times[0]
        ).total_seconds()
        return observed_duration_seconds >= self.RETRY_ESCALATION_MIN_DURATION_SECONDS

    def matches(self, pod, events, context) -> bool:
        init_statuses = pod.get("status", {}).get("initContainerStatuses", [])
        if not init_statuses:
            return False

        if self._retry_escalation_present(pod, context):
            return False

        for cs in init_statuses:
            state = cs.get("state", {})
            waiting = state.get("waiting", {})
            terminated = state.get("terminated", {})

            reason = waiting.get("reason") or terminated.get("reason")

            if reason in self.FAILURE_REASONS:
                return True

        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        failing_init = "<unknown>"

        for cs in pod.get("status", {}).get("initContainerStatuses", []):
            state = cs.get("state", {})
            waiting = state.get("waiting", {})
            terminated = state.get("terminated", {})
            reason = waiting.get("reason") or terminated.get("reason")

            if reason in self.FAILURE_REASONS:
                failing_init = cs.get("name")
                break

        chain = CausalChain(
            causes=[
                Cause(
                    code="INIT_CONTAINER_FAILURE_DETECTED",
                    message=f"Init container {failing_init} entered failure state",
                    role="container_health_context",
                ),
                Cause(
                    code="INIT_CONTAINER_FAILURE",
                    message="Init container failed during Pod initialization",
                    role="container_health_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_INITIALIZATION_BLOCKED",
                    message="Main containers not started due to init container failure",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "Init container failure prevented pod startup",
            "confidence": 0.96,
            "causes": chain,
            "evidence": [
                "Init container entered failure state",
                "Main containers not fully initialized",
                "Pod stuck in initialization phase",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Pod initialization blocked by init container failure"
                ],
                f"container:{failing_init}": [
                    "Init container failed prior to main container start"
                ],
            },
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                f"kubectl logs {pod_name} -c {failing_init}",
                "Validate init container image and commands",
                "Inspect external dependencies required during initialization",
            ],
            "blocking": True,
        }
