from __future__ import annotations

import re
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class PriorityClassNotFoundRule(FailureRule):
    """
    Detects workloads blocked because they reference a missing PriorityClass.

    Real-world behavior:
    - in normal Kubernetes clusters, PriorityClass is resolved by admission
      before the Pod is persisted; a missing class usually appears as a
      FailedCreate/forbidden event on the controller rather than a scheduler
      rejection on an existing Pod
    - existing Pods are not invalidated when a PriorityClass is later deleted,
      because admission has already copied the numeric priority into spec.priority
    - scheduler-side or custom admission integrations may still surface the
      same condition as FailedScheduling, so event matching accepts both shapes

    The rule therefore requires an explicit missing-priority-class signal or an
    unresolved Pod priority field. A bare absent PriorityClass object is only
    supporting evidence, not enough by itself.
    """

    name = "PriorityClassNotFound"
    category = "Scheduling"
    priority = 17
    deterministic = False
    phases = ["Pending", "Unknown"]
    blocks = ["FailedScheduling"]

    requires = {
        "pod": True,
        "events": True,
        "optional_objects": ["priorityclass"],
    }

    CACHE_KEY = "_priority_class_notfound_candidate"
    WINDOW_MINUTES = 60

    MISSING_CLASS_MARKERS = (
        "no priorityclass with name",
        "no priority class with name",
        "priorityclass not found",
        "priority class not found",
        "could not find priorityclass",
        "could not find priority class",
        "failed to get priorityclass",
        "failed to get priority class",
        "priorityclass.scheduling.k8s.io",
        "priorityclasses.scheduling.k8s.io",
    )
    FAILURE_REASONS = {
        "failedcreate",
        "failedscheduling",
        "failedadmission",
        "createfailed",
        "failedcreatepod",
    }

    def _priority_class_name(self, pod: dict[str, Any]) -> str | None:
        name = pod.get("spec", {}).get("priorityClassName")
        if isinstance(name, str) and name.strip():
            return name.strip()
        return None

    def _pod_priority_is_unresolved(self, pod: dict[str, Any]) -> bool:
        spec = pod.get("spec", {}) or {}
        return spec.get("priority") is None

    def _message(self, value: Any) -> str:
        return str(value or "").strip()

    def _reason(self, event: dict[str, Any]) -> str:
        return self._message(event.get("reason")).lower()

    def _namespace(self, obj: dict[str, Any]) -> str:
        return str(obj.get("metadata", {}).get("namespace", "default"))

    def _priorityclasses(self, context: dict[str, Any]) -> dict[str, dict[str, Any]]:
        objects = context.get("objects", {}) or {}
        raw = objects.get("priorityclass") or objects.get("priorityclasses") or {}

        if isinstance(raw, dict):
            return {name: obj for name, obj in raw.items() if isinstance(obj, dict)}

        if isinstance(raw, list):
            result = {}
            for obj in raw:
                if not isinstance(obj, dict):
                    continue
                name = obj.get("metadata", {}).get("name")
                if isinstance(name, str) and name:
                    result[name] = obj
            return result

        return {}

    def _priorityclass_graph_present(self, context: dict[str, Any]) -> bool:
        objects = context.get("objects", {}) or {}
        return "priorityclass" in objects or "priorityclasses" in objects

    def _priorityclass_exists(self, context: dict[str, Any], name: str) -> bool:
        return name in self._priorityclasses(context)

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

    def _event_namespace_matches(
        self,
        event: dict[str, Any],
        pod_namespace: str,
    ) -> bool:
        involved = event.get("involvedObject") or {}
        if not isinstance(involved, dict):
            return True
        event_namespace = involved.get("namespace")
        return event_namespace in (None, "", pod_namespace)

    def _event_mentions_pod(
        self,
        event: dict[str, Any],
        *,
        pod_name: str,
        pod_namespace: str,
    ) -> bool:
        involved = event.get("involvedObject") or {}
        if isinstance(involved, dict):
            kind = self._message(involved.get("kind")).lower()
            name = self._message(involved.get("name"))
            namespace = self._message(involved.get("namespace")) or pod_namespace
            if namespace != pod_namespace:
                return False
            if kind == "pod" and name == pod_name:
                return True

        msg = self._message(event.get("message")).lower()
        return bool(pod_name and pod_name.lower() in msg)

    def _message_names_class(self, message: str, priority_class_name: str) -> bool:
        msg = message.lower()
        class_name = priority_class_name.lower()

        if class_name in msg:
            return True

        quoted_names = re.findall(r'["\']([^"\']+)["\']', message)
        return any(name.lower() == class_name for name in quoted_names)

    def _looks_missing_priority_class(
        self,
        event: dict[str, Any],
        priority_class_name: str,
    ) -> bool:
        reason = self._reason(event)
        message = self._message(event.get("message"))
        msg = message.lower()

        if reason and reason not in self.FAILURE_REASONS:
            has_marker = any(marker in msg for marker in self.MISSING_CLASS_MARKERS)
            return has_marker and self._message_names_class(
                message, priority_class_name
            )

        if not any(marker in msg for marker in self.MISSING_CLASS_MARKERS):
            return False

        if not self._message_names_class(message, priority_class_name):
            return False

        return "not found" in msg or "no priority" in msg or "forbidden" in msg

    def _candidate(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        priority_class_name = self._priority_class_name(pod)
        if not priority_class_name:
            return None

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        pod_namespace = self._namespace(pod)
        graph_present = self._priorityclass_graph_present(context)
        class_exists = self._priorityclass_exists(context, priority_class_name)
        priority_unresolved = self._pod_priority_is_unresolved(pod)

        matching_events = []
        for event in self._candidate_events(events, context):
            if not isinstance(event, dict):
                continue
            if not self._event_namespace_matches(event, pod_namespace):
                continue
            if not self._looks_missing_priority_class(event, priority_class_name):
                continue
            if not self._event_mentions_pod(
                event,
                pod_name=pod_name,
                pod_namespace=pod_namespace,
            ):
                involved = event.get("involvedObject") or {}
                if isinstance(involved, dict) and involved.get("kind") == "Pod":
                    continue
            matching_events.append(event)

        if matching_events:
            return {
                "priority_class_name": priority_class_name,
                "priorityclass_graph_present": graph_present,
                "class_exists": class_exists,
                "priority_unresolved": priority_unresolved,
                "events": matching_events,
            }

        if graph_present and priority_unresolved and not class_exists:
            return {
                "priority_class_name": priority_class_name,
                "priorityclass_graph_present": graph_present,
                "class_exists": class_exists,
                "priority_unresolved": priority_unresolved,
                "events": [],
            }

        return None

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
            raise ValueError("PriorityClassNotFound explain() called without match")

        priority_class_name = candidate["priority_class_name"]
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        namespace = self._namespace(pod)
        matching_events = candidate.get("events", [])

        event_messages = [
            self._message(event.get("message"))
            for event in matching_events
            if self._message(event.get("message"))
        ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="POD_REFERENCES_PRIORITYCLASS",
                    message=f"Pod requests PriorityClass '{priority_class_name}'",
                    role="workload_context",
                ),
                Cause(
                    code="PRIORITYCLASS_NOT_FOUND",
                    message="Kubernetes cannot resolve the requested PriorityClass",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_CREATE_OR_SCHEDULING_BLOCKED",
                    message="Pod admission or scheduling cannot proceed until priority is resolved",
                    role="workload_symptom",
                ),
            ]
        )

        evidence = [
            f"Pod.spec.priorityClassName={priority_class_name}",
        ]
        object_evidence = {
            f"pod:{pod_name}": [
                f"priorityClassName={priority_class_name}",
            ]
        }

        if candidate["priorityclass_graph_present"] and not candidate["class_exists"]:
            evidence.append(
                "Referenced PriorityClass is absent from the current object graph"
            )
            object_evidence[f"pod:{pod_name}"].append(
                "Referenced PriorityClass object not found"
            )
        elif matching_events:
            evidence.append(
                "PriorityClass objects were not included; using admission or scheduler event as the authoritative signal"
            )

        if candidate["priority_unresolved"]:
            evidence.append("Pod.spec.priority is not populated")
            object_evidence[f"pod:{pod_name}"].append("spec.priority is unset")

        if matching_events:
            evidence.append(
                f"Missing PriorityClass failure event observed {len(matching_events)} time(s)"
            )
            evidence.extend(event_messages[:2])
            object_evidence[f"pod:{pod_name}"].extend(event_messages[:3])

        confidence = 0.9
        if (
            matching_events
            and candidate["priorityclass_graph_present"]
            and not candidate["class_exists"]
        ):
            confidence = 0.96
        elif matching_events:
            confidence = 0.94
        elif candidate["priority_unresolved"] and not candidate["class_exists"]:
            confidence = 0.86

        ns_flag = f" -n {namespace}" if namespace else ""

        return {
            "rule": self.name,
            "root_cause": f"Pod references missing PriorityClass '{priority_class_name}'",
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "The PriorityClass was not created before the workload was applied",
                "priorityClassName contains a typo or environment-specific name",
                "A GitOps or Helm value references a PriorityClass that is not installed in this cluster",
                "The PriorityClass was deleted while controllers were still creating replacement Pods",
            ],
            "suggested_checks": [
                f"kubectl get priorityclass {priority_class_name}",
                "kubectl get priorityclass",
                f"kubectl describe pod {pod_name}{ns_flag}",
                "Inspect the owning Deployment/ReplicaSet/StatefulSet events for FailedCreate messages",
                "Create the missing PriorityClass or update priorityClassName to an existing class",
            ],
        }
