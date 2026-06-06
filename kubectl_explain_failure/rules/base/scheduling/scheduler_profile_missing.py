from __future__ import annotations

import re
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class SchedulerProfileMissingRule(FailureRule):
    """
    Detects Pods blocked because they reference a scheduler profile name that
    does not exist in the kube-scheduler configuration.

    Real-world behavior:
    - kube-scheduler supports multiple scheduling profiles since Kubernetes 1.18
      via KubeSchedulerProfile objects in its configuration file
    - a Pod opts in to a named profile by setting
      spec.schedulerName to something other than "default-scheduler"
    - when a Pod's schedulerName does not correspond to any configured profile,
      the scheduler ignores the Pod entirely; no FailedScheduling event is ever
      emitted, so the Pod simply sits in Pending indefinitely
    - some environments surface this as a FailedScheduling event with a message
      such as "no scheduler found for pod" or "scheduler not found",
      particularly custom schedulers, secondary schedulers (e.g. volcano,
      yunikorn, coscheduler), or Kubernetes versions that validate the field
    - the distinguishing symptom is that the Pod is Pending with a non-default
      schedulerName while no scheduling activity (FailedScheduling, Scheduled)
      has occurred at all, OR explicit events reference the missing scheduler
    - a schedulerName of "default-scheduler" is always present and is excluded

    Scope:
    - scheduler configuration layer
    - Deterministic when schedulerName is non-default and no scheduling
      activity is observed
    - Non-deterministic (event-only) path handles custom/secondary schedulers
      that do emit explicit "not found" events

    Exclusions:
    - Pods with schedulerName == "default-scheduler" (always present)
    - Pods whose scheduler is present and has already emitted FailedScheduling
      or Scheduled events (the scheduler is active, so its profile exists)
    - scheduling gates (handled by PodSchedulingGateBlocked)
    """

    name = "SchedulerProfileMissing"
    category = "Scheduling"
    priority = 89
    deterministic = False
    phases = ["Pending", "Unknown"]

    blocks = [
        "FailedScheduling",
        "PendingUnschedulable",
        "InsufficientResources",
        "NodeSelectorMismatch",
        "NodeAffinityRequiredMismatch",
        "AffinityUnsatisfiable",
        "UnschedulableTaint",
    ]

    requires = {
        "pod": True,
        "optional_objects": ["schedulerprofile", "configmap"],
    }

    CACHE_KEY = "_scheduler_profile_missing_candidate"
    WINDOW_MINUTES = 60

    DEFAULT_SCHEDULER = "default-scheduler"

    # Event message patterns emitted by the scheduler or custom schedulers
    # when a scheduler/profile cannot be found for a Pod
    MISSING_SCHEDULER_MARKERS = (
        "no scheduler found for pod",
        "scheduler not found",
        "no scheduler named",
        "unknown scheduler",
        "scheduler does not exist",
        "scheduler profile not found",
        "profile not found",
        "no scheduling profile",
        "no profile found",
        "cannot find scheduler",
        "could not find scheduler",
        "failed to find scheduler",
        "scheduler is not registered",
        "scheduler plugin not found",
        "no plugin named",
        "unregistered scheduler",
    )

    # Scheduler names that are always built-in and can never be "missing"
    BUILTIN_SCHEDULER_NAMES = frozenset(
        {
            "default-scheduler",
        }
    )

    # Reasons that indicate the scheduler *is* active for this Pod
    SCHEDULER_ACTIVE_REASONS = frozenset(
        {
            "Scheduled",
            "FailedScheduling",
            "Preempted",
            "PreemptingNominated",
        }
    )

    # Volcano / YuniKorn / coscheduler / etc. secondary-scheduler names that
    # are common enough to appear in real clusters
    KNOWN_SECONDARY_SCHEDULERS = (
        "volcano",
        "yunikorn",
        "coscheduler",
        "koord-scheduler",
        "scheduler-plugins",
        "descheduler",
        "secondary-scheduler",
    )

    _QUOTED_NAME_RE = re.compile(r'["\']([^"\']{1,128})["\']')

    def _message(self, value: Any) -> str:
        return str(value or "").strip()

    def _namespace(self, obj: dict[str, Any]) -> str:
        return self._message(obj.get("metadata", {}).get("namespace")) or "default"

    def _scheduler_name(self, pod: dict[str, Any]) -> str | None:
        name = pod.get("spec", {}).get("schedulerName")
        if not isinstance(name, str):
            return None
        name = name.strip()
        if not name:
            return None
        return name

    def _pod_is_scheduled(self, pod: dict[str, Any]) -> bool:
        if pod.get("spec", {}).get("nodeName"):
            return True
        for condition in pod.get("status", {}).get("conditions", []) or []:
            if (
                condition.get("type") == "PodScheduled"
                and str(condition.get("status", "")).lower() == "true"
            ):
                return True
        return False

    def _pod_is_gated(self, pod: dict[str, Any]) -> bool:
        gates = pod.get("spec", {}).get("schedulingGates")
        return bool(gates)

    def _candidate_events(
        self,
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        timeline = context.get("timeline")
        if isinstance(timeline, Timeline):
            recent = timeline.events_within_window(self.WINDOW_MINUTES)
            return recent or timeline.events
        return events or []

    def _event_targets_pod(
        self,
        event: dict[str, Any],
        *,
        pod_name: str,
        pod_namespace: str,
    ) -> bool:
        involved = event.get("involvedObject") or {}
        if isinstance(involved, dict):
            kind = self._message(involved.get("kind")).lower()
            ev_name = self._message(involved.get("name"))
            ev_namespace = self._message(involved.get("namespace")) or pod_namespace

            if ev_namespace != pod_namespace:
                return False
            if kind == "pod" and ev_name == pod_name:
                return True

        msg = self._message(event.get("message")).lower()
        return bool(pod_name and pod_name.lower() in msg)

    def _looks_scheduler_missing_event(
        self,
        event: dict[str, Any],
        scheduler_name: str,
    ) -> bool:
        message = self._message(event.get("message"))
        reason = self._message(event.get("reason"))
        combined = f"{reason} {message}".lower()

        if not any(marker in combined for marker in self.MISSING_SCHEDULER_MARKERS):
            return False

        # Prefer events that explicitly name the scheduler
        if scheduler_name.lower() in combined:
            return True

        # Accept generic "scheduler not found" without a name only when the
        # event reason is scheduling-related
        reason_lower = reason.lower()
        return reason_lower in {
            "failedscheduling",
            "failedcreate",
            "schedulerfailed",
            "noscheduler",
        }

    def _scheduler_name_in_event(
        self,
        event: dict[str, Any],
        scheduler_name: str,
    ) -> bool:
        combined = (
            self._message(event.get("reason"))
            + " "
            + self._message(event.get("message"))
        ).lower()
        return scheduler_name.lower() in combined

    def _scheduler_active_for_pod(
        self,
        events: list[dict[str, Any]],
        context: dict[str, Any],
        *,
        pod_name: str,
        pod_namespace: str,
        scheduler_name: str,
    ) -> bool:
        """
        Return True if there is evidence that the scheduler is *active* for
        this Pod (i.e. the scheduler exists and is processing the Pod).
        """
        for event in self._candidate_events(events, context):
            reason = self._message(event.get("reason"))
            if reason not in self.SCHEDULER_ACTIVE_REASONS:
                continue
            if not self._event_targets_pod(
                event, pod_name=pod_name, pod_namespace=pod_namespace
            ):
                continue
            return True
        return False

    def _known_profiles_from_configmap(
        self,
        context: dict[str, Any],
        scheduler_name: str,
    ) -> bool | None:
        """
        Inspect kube-scheduler ConfigMaps for KubeSchedulerConfiguration.
        Returns:
          True  - profile found
          False - configmap present but profile absent
          None  - not determinable
        """
        configmaps = context.get("objects", {}).get("configmap", {}) or {}
        for cm in configmaps.values():
            if not isinstance(cm, dict):
                continue

            metadata = cm.get("metadata", {})
            cm_name = str(metadata.get("name", "") or "").lower()
            cm_ns = str(metadata.get("namespace", "kube-system") or "kube-system")

            # Only look at scheduler-related configmaps in kube-system
            if cm_ns != "kube-system":
                continue
            if not any(marker in cm_name for marker in ("scheduler", "kube-scheduler")):
                continue

            data = cm.get("data", {}) or {}
            for raw_value in data.values():
                if not isinstance(raw_value, str):
                    continue
                lowered = raw_value.lower()
                # KubeSchedulerConfiguration profiles[].schedulerName
                if "schedulername" not in lowered and "profiles" not in lowered:
                    continue
                if scheduler_name.lower() in lowered:
                    return True
                # ConfigMap present and mentions profiles but our name is absent
                if "profiles" in lowered:
                    return False

        return None

    def _candidate(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        # Scheduling gates are a separate concern
        if self._pod_is_gated(pod):
            return None

        scheduler_name = self._scheduler_name(pod)
        if not scheduler_name:
            return None

        # Built-in schedulers are never "missing"
        if scheduler_name in self.BUILTIN_SCHEDULER_NAMES:
            return None

        phase = pod.get("status", {}).get("phase", "Unknown")
        if phase not in {"Pending", "Unknown"}:
            return None

        if self._pod_is_scheduled(pod):
            return None

        pod_name = self._message(pod.get("metadata", {}).get("name")) or "<unknown>"
        pod_namespace = self._namespace(pod)

        # If the scheduler is demonstrably active for this pod, it exists
        if self._scheduler_active_for_pod(
            events,
            context,
            pod_name=pod_name,
            pod_namespace=pod_namespace,
            scheduler_name=scheduler_name,
        ):
            return None

        # --- Gather explicit event signals ---
        matching_events = []
        for event in self._candidate_events(events, context):
            if not isinstance(event, dict):
                continue
            if not self._looks_scheduler_missing_event(event, scheduler_name):
                continue
            if not self._event_targets_pod(
                event, pod_name=pod_name, pod_namespace=pod_namespace
            ):
                involved = event.get("involvedObject") or {}
                if isinstance(involved, dict) and involved.get("kind") == "Pod":
                    continue
            matching_events.append(event)

        # --- ConfigMap-based deterministic signal ---
        configmap_result = self._known_profiles_from_configmap(context, scheduler_name)

        # Accept when:
        # 1. Explicit event says scheduler/profile missing, OR
        # 2. ConfigMap is present but profile name is absent (deterministic), OR
        # 3. schedulerName looks like a secondary scheduler and there is zero
        #    scheduling activity for the Pod (high confidence heuristic)
        is_known_secondary = any(
            token in scheduler_name.lower() for token in self.KNOWN_SECONDARY_SCHEDULERS
        )

        has_event_signal = bool(matching_events)
        has_configmap_signal = configmap_result is False
        has_silent_pending_signal = (
            not has_event_signal and not has_configmap_signal and is_known_secondary
        )

        if not (has_event_signal or has_configmap_signal or has_silent_pending_signal):
            # No signal at all; only proceed for truly non-default names where
            # the Pod has been Pending with zero scheduler activity.  This is
            # the weakest signal (low confidence) but still useful for catch-all.
            # We require the schedulerName to be clearly non-standard.
            if scheduler_name.lower() == self.DEFAULT_SCHEDULER:
                return None
            # Without any corroborating evidence require at least one of the
            # above signals to avoid false positives on custom schedulers that
            # are legitimately slow.
            return None

        return {
            "scheduler_name": scheduler_name,
            "events": matching_events,
            "has_event_signal": has_event_signal,
            "has_configmap_signal": has_configmap_signal,
            "is_known_secondary": is_known_secondary,
            "configmap_result": configmap_result,
        }

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, events, context)
        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False
        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(pod, events, context)
        if candidate is None:
            raise ValueError("SchedulerProfileMissing explain() called without match")

        pod_name = self._message(pod.get("metadata", {}).get("name")) or "<unknown>"
        namespace = self._namespace(pod)
        scheduler_name = candidate["scheduler_name"]
        matching_events = candidate.get("events", [])

        event_messages = [
            self._message(event.get("message"))
            for event in matching_events
            if self._message(event.get("message"))
        ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_REFERENCES_SCHEDULER_PROFILE",
                    message=f"Pod requests scheduler '{scheduler_name}' via spec.schedulerName",
                    role="workload_context",
                ),
                Cause(
                    code="SCHEDULER_PROFILE_MISSING",
                    message=(
                        f"No running scheduler or scheduling profile named "
                        f"'{scheduler_name}' is available in the cluster"
                    ),
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_IGNORED_BY_SCHEDULER",
                    message=(
                        "Pod remains Pending indefinitely because no scheduler "
                        "is watching or processing it"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod.spec.schedulerName={scheduler_name}",
            f"Pod phase={pod.get('status', {}).get('phase', 'Pending')}",
            "No FailedScheduling or Scheduled events observed for this Pod",
        ]

        object_evidence: dict[str, list[str]] = {
            f"pod:{namespace}/{pod_name}": [
                f"spec.schedulerName={scheduler_name}",
                "Pod has not been processed by any scheduler",
            ]
        }

        if candidate["has_configmap_signal"]:
            evidence.append(
                f"kube-scheduler ConfigMap was inspected and does not contain "
                f"a profile for '{scheduler_name}'"
            )
            object_evidence["configmap:kube-scheduler"] = [
                f"Profile '{scheduler_name}' is absent from KubeSchedulerConfiguration"
            ]

        if candidate["is_known_secondary"]:
            evidence.append(
                f"'{scheduler_name}' matches a known secondary/batch scheduler "
                "name; the scheduler may not be deployed in this cluster"
            )

        if event_messages:
            evidence.append(
                f"Scheduler-missing event observed {len(matching_events)} time(s)"
            )
            evidence.extend(event_messages[:2])
            object_evidence[f"pod:{namespace}/{pod_name}"].extend(event_messages[:3])

        confidence = 0.82
        if candidate["has_event_signal"] and candidate["has_configmap_signal"]:
            confidence = 0.97
        elif candidate["has_event_signal"]:
            confidence = 0.94
        elif candidate["has_configmap_signal"]:
            confidence = 0.93
        elif candidate["is_known_secondary"]:
            confidence = 0.86

        ns_flag = f" -n {namespace}" if namespace else ""

        return {
            "rule": self.name,
            "root_cause": (
                f"Pod references scheduler profile '{scheduler_name}' "
                "which does not exist or is not running"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": list(dict.fromkeys(evidence)),
            "object_evidence": {
                key: list(dict.fromkeys(values))
                for key, values in object_evidence.items()
            },
            "likely_causes": [
                f"The secondary scheduler or scheduling framework '{scheduler_name}' "
                "is not deployed in this cluster",
                "The kube-scheduler KubeSchedulerConfiguration does not define "
                f"a profile with schedulerName '{scheduler_name}'",
                f"'{scheduler_name}' contains a typo or refers to an environment-specific profile name",
                "A GitOps or Helm deployment applied the workload before the "
                "custom scheduler or profile was installed",
                "The scheduler Pod (volcano, yunikorn, coscheduler, etc.) "
                "crashed or was removed after the workload was created",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}{ns_flag}",
                f"kubectl get pods -A | grep {scheduler_name}",
                "kubectl -n kube-system get configmap -l component=kube-scheduler -o yaml",
                "Verify the scheduler deployment or DaemonSet is running and healthy",
                f"kubectl get events -n {namespace} --field-selector "
                f"involvedObject.name={pod_name}",
                "Check kube-scheduler logs for profile registration",
            ],
        }
