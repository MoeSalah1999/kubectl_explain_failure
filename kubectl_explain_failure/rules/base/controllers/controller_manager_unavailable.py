from __future__ import annotations

from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ControllerManagerUnavailableRule(FailureRule):
    """
    Detects workload reconciliation failures that are downstream of an
    unavailable kube-controller-manager instance.

    Real-world interpretation:
    - kube-controller-manager is crashlooping, not passing health checks, or
      losing leader election / API connectivity
    - workload controllers then stop reconciling desired state in a timely way
    - rollout symptoms such as missing replicas or zero available replicas are
      therefore downstream controller effects rather than the primary cause
    """

    name = "ControllerManagerUnavailable"
    category = "Controller"
    priority = 58
    deterministic = True
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "context": ["timeline"],
        "objects": ["pod"],
        "optional_objects": ["deployment", "replicaset", "statefulset", "daemonset"],
    }
    blocks = [
        "DeploymentReplicaMismatch",
        "DeploymentProgressDeadlineExceeded",
        "ReplicaSetCreateFailure",
        "ReplicaSetUnavailable",
    ]

    WINDOW_MINUTES = 20
    CACHE_KEY = "_controller_manager_unavailable_candidate"
    CONTROLLER_MANAGER_NAMES = (
        "kube-controller-manager",
        "controller-manager",
    )
    OUTAGE_REASONS = {
        "backoff",
        "failed",
        "unhealthy",
        "leaderelection",
        "failedleaderelection",
    }
    OUTAGE_MARKERS = (
        "kube-controller-manager",
        "failed to renew lease",
        "failed to acquire lease",
        "leaderelection lost",
        "leadership lost",
        "error retrieving resource lock",
        "healthz",
        "readyz",
        "10257",
        "dial tcp",
        "i/o timeout",
        "connection refused",
        "apiserver",
        "the server was unable to return a response",
    )

    def _parse_ts(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_ts(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_ts(event.get("firstTimestamp"))
            or self._parse_ts(event.get("eventTime"))
            or self._parse_ts(event.get("lastTimestamp"))
            or self._parse_ts(event.get("timestamp"))
        )

    def _ordered_recent(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        items = list(enumerate(recent))
        return [
            event
            for _, event in sorted(
                items,
                key=lambda item: (
                    1 if self._event_ts(item[1]) is None else 0,
                    self._event_ts(item[1]) or datetime.min,
                    item[0],
                ),
            )
        ]

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message", "")).lower()

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason", "")).lower()

    def _pod_text(self, pod_obj: dict[str, Any]) -> str:
        metadata = pod_obj.get("metadata", {})
        labels = metadata.get("labels", {}) or {}
        spec = pod_obj.get("spec", {}) or {}
        status = pod_obj.get("status", {}) or {}

        values = [
            metadata.get("name", ""),
            metadata.get("namespace", ""),
            *labels.keys(),
            *labels.values(),
            *[
                c.get("name", "")
                for c in spec.get("containers", []) or []
                if isinstance(c, dict)
            ],
            *[
                c.get("name", "")
                for c in status.get("containerStatuses", []) or []
                if isinstance(c, dict)
            ],
        ]
        return " ".join(str(value).lower() for value in values if value)

    def _controller_manager_pods(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        pod_objects = context.get("objects", {}).get("pod", {})
        return [
            pod_obj
            for pod_obj in pod_objects.values()
            if isinstance(pod_obj, dict)
            and pod_obj.get("metadata", {}).get("namespace") == "kube-system"
            and any(
                marker in self._pod_text(pod_obj)
                for marker in self.CONTROLLER_MANAGER_NAMES
            )
        ]

    def _container_state_name(self, status: dict[str, Any]) -> str:
        state = status.get("state", {}) or {}
        if "waiting" in state:
            return "waiting"
        if "terminated" in state:
            return "terminated"
        if "running" in state:
            return "running"
        return "unknown"

    def _pod_outage_status(
        self, controller_pod: dict[str, Any]
    ) -> dict[str, Any] | None:
        statuses = controller_pod.get("status", {}).get("containerStatuses", []) or []
        for status in statuses:
            if not isinstance(status, dict):
                continue
            name = str(status.get("name", "")).lower()
            if "controller-manager" not in name:
                continue
            state = status.get("state", {}) or {}
            waiting = state.get("waiting", {}) or {}
            terminated = state.get("terminated", {}) or {}
            if (
                not bool(status.get("ready", False))
                or waiting.get("reason") == "CrashLoopBackOff"
                or terminated
                or int(status.get("restartCount", 0) or 0) > 0
            ):
                return status
        return None

    def _event_targets_pod(
        self, event: dict[str, Any], pod_obj: dict[str, Any]
    ) -> bool:
        involved = event.get("involvedObject", {}) or {}
        if not isinstance(involved, dict):
            return False
        name = pod_obj.get("metadata", {}).get("name")
        namespace = pod_obj.get("metadata", {}).get("namespace")
        if involved.get("name") and involved.get("name") != name:
            return False
        if involved.get("namespace") and involved.get("namespace") != namespace:
            return False
        kind = str(involved.get("kind", "")).lower()
        return kind in {"", "pod"}

    def _outage_events(
        self,
        controller_pod: dict[str, Any],
        ordered_events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for event in ordered_events:
            if not self._event_targets_pod(event, controller_pod):
                continue
            reason = self._reason(event)
            message = self._message(event)
            if reason not in self.OUTAGE_REASONS:
                continue
            if any(marker in message for marker in self.OUTAGE_MARKERS):
                results.append(event)
        return results

    def _owner_ref(self, obj: dict[str, Any], kind: str) -> str | None:
        for ref in obj.get("metadata", {}).get("ownerReferences", []) or []:
            if str(ref.get("kind", "")).lower() == kind.lower() and ref.get("name"):
                return str(ref["name"])
        return None

    def _find_named_object(
        self,
        objects: dict[str, Any],
        kind: str,
        name: str,
        namespace: str,
    ) -> dict[str, Any] | None:
        direct = objects.get(kind, {}).get(name)
        if isinstance(direct, dict):
            if direct.get("metadata", {}).get("namespace", "default") == namespace:
                return direct
        for obj in objects.get(kind, {}).values():
            if not isinstance(obj, dict):
                continue
            metadata = obj.get("metadata", {})
            if metadata.get("name") != name:
                continue
            if metadata.get("namespace", "default") != namespace:
                continue
            return obj
        return None

    def _workload_symptom(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, str] | None:
        objects = context.get("objects", {})
        namespace = pod.get("metadata", {}).get("namespace", "default")

        deployment_name = self._owner_ref(pod, "Deployment")
        rs_name = self._owner_ref(pod, "ReplicaSet")
        if deployment_name is None and rs_name is not None:
            rs_obj = self._find_named_object(objects, "replicaset", rs_name, namespace)
            if rs_obj is not None:
                deployment_name = self._owner_ref(rs_obj, "Deployment")

        if deployment_name:
            deployment = self._find_named_object(
                objects,
                "deployment",
                deployment_name,
                namespace,
            )
            if deployment:
                status = deployment.get("status", {}) or {}
                desired = int(
                    status.get(
                        "replicas", deployment.get("spec", {}).get("replicas", 0)
                    )
                    or 0
                )
                available = int(status.get("availableReplicas", 0) or 0)
                updated = int(status.get("updatedReplicas", 0) or 0)
                if desired > 0 and available < desired:
                    return {
                        "kind": "deployment",
                        "name": deployment_name,
                        "message": f"Deployment '{deployment_name}' remains at {available}/{desired} available replicas while only {updated}/{desired} replicas are updated",
                    }

        if rs_name:
            rs_obj = self._find_named_object(objects, "replicaset", rs_name, namespace)
            if rs_obj:
                status = rs_obj.get("status", {}) or {}
                available = int(status.get("availableReplicas", 0) or 0)
                if available == 0:
                    return {
                        "kind": "replicaset",
                        "name": rs_name,
                        "message": f"ReplicaSet '{rs_name}' has zero available replicas",
                    }
                conditions = status.get("conditions", []) or []
                if any(
                    cond.get("type") == "ReplicaFailure"
                    and str(cond.get("status", "")).lower() == "true"
                    for cond in conditions
                ):
                    return {
                        "kind": "replicaset",
                        "name": rs_name,
                        "message": f"ReplicaSet '{rs_name}' reports ReplicaFailure=True",
                    }

        statefulset_name = self._owner_ref(pod, "StatefulSet")
        if statefulset_name:
            sts = self._find_named_object(
                objects, "statefulset", statefulset_name, namespace
            )
            if sts:
                status = sts.get("status", {}) or {}
                desired = int(sts.get("spec", {}).get("replicas", 0) or 0)
                ready = int(status.get("readyReplicas", 0) or 0)
                if desired > 0 and ready < desired:
                    return {
                        "kind": "statefulset",
                        "name": statefulset_name,
                        "message": f"StatefulSet '{statefulset_name}' remains at {ready}/{desired} ready replicas",
                    }

        daemonset_name = self._owner_ref(pod, "DaemonSet")
        if daemonset_name:
            ds = self._find_named_object(
                objects, "daemonset", daemonset_name, namespace
            )
            if ds:
                status = ds.get("status", {}) or {}
                desired = int(status.get("desiredNumberScheduled", 0) or 0)
                available = int(status.get("numberAvailable", 0) or 0)
                if desired > 0 and available < desired:
                    return {
                        "kind": "daemonset",
                        "name": daemonset_name,
                        "message": f"DaemonSet '{daemonset_name}' remains at {available}/{desired} available nodes",
                    }

        return None

    def _candidate(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        symptom = self._workload_symptom(pod, context)
        if symptom is None:
            return None

        ordered_events = self._ordered_recent(timeline)
        if not ordered_events:
            return None

        best: dict[str, Any] | None = None
        for controller_pod in self._controller_manager_pods(context):
            outage_status = self._pod_outage_status(controller_pod)
            if outage_status is None:
                continue
            outage_events = self._outage_events(controller_pod, ordered_events)
            if not outage_events:
                continue

            candidate = {
                "controller_pod_name": controller_pod.get("metadata", {}).get(
                    "name", "<unknown>"
                ),
                "controller_container_name": outage_status.get(
                    "name", "kube-controller-manager"
                ),
                "controller_restart_count": int(
                    outage_status.get("restartCount", 0) or 0
                ),
                "controller_state_name": self._container_state_name(outage_status),
                "outage_message": str(outage_events[-1].get("message", "")).strip(),
                "symptom": symptom,
            }
            if (
                best is None
                or candidate["controller_restart_count"]
                > best["controller_restart_count"]
            ):
                best = candidate

        return best

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
            raise ValueError(
                "ControllerManagerUnavailable explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        controller_pod_name = candidate["controller_pod_name"]
        controller_container_name = candidate["controller_container_name"]
        symptom = candidate["symptom"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="WORKLOAD_REQUIRES_CONTROLLER_RECONCILIATION",
                    message="This workload depends on kube-controller-manager to reconcile desired controller state",
                    role="controller_context",
                ),
                Cause(
                    code="CONTROLLER_MANAGER_UNAVAILABLE",
                    message="kube-controller-manager is unavailable due to crash, failed health checks, or lost leadership",
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="WORKLOAD_RECONCILIATION_STALLED",
                    message="Controller-owned workload state is no longer converging while kube-controller-manager is unavailable",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "kube-controller-manager is unavailable, so workload controllers cannot reconcile desired state",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Recent kube-controller-manager outage targets pod '{controller_pod_name}' with container '{controller_container_name}' state={candidate['controller_state_name']} restartCount={candidate['controller_restart_count']}",
                f"Representative controller-manager outage signal: {candidate['outage_message']}",
                f"Workload reconciliation symptom: {symptom['message']}",
            ],
            "object_evidence": {
                f"pod:{controller_pod_name}": [
                    candidate["outage_message"],
                ],
                f"{symptom['kind']}:{symptom['name']}": [
                    symptom["message"],
                ],
                f"pod:{pod_name}": [
                    "The pod belongs to a controller-managed workload whose desired state is not converging while kube-controller-manager is unavailable"
                ],
            },
            "likely_causes": [
                "kube-controller-manager lost leadership or cannot renew its lease against the API server",
                "The controller-manager process is crashlooping or failing its health checks on the control-plane node",
                "Control-plane network or API connectivity issues are preventing controllers from reconciling desired workload state",
                "Static-pod or manifest drift on the control-plane node left kube-controller-manager unavailable",
            ],
            "suggested_checks": [
                f"kubectl describe pod {controller_pod_name} -n kube-system",
                f"kubectl logs -n kube-system {controller_pod_name} -c {controller_container_name}",
                "Inspect kube-controller-manager leader election and API connectivity errors",
                f"kubectl describe {symptom['kind']} {symptom['name']}",
            ],
        }
