from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class NamespaceTerminatingBlocksPodRule(FailureRule):
    """
    Detects pod creation or update failures caused by the namespace being
    in Terminating state.

    Real-world interpretation:
    - namespace deletion has started
    - namespace has a deletionTimestamp and/or phase=Terminating
    - API server rejects creation of new resources
    - controllers repeatedly fail to create replacement pods
    - workload symptoms are downstream effects of namespace shutdown

    This is an API machinery / namespace lifecycle issue rather than a
    pod scheduling or runtime problem.
    """

    name = "NamespaceTerminatingBlocksPod"
    category = "Compound"
    priority = 93
    deterministic = True

    blocks = [
        "ResourceQuotaExceeded",
        "AdmissionWebhookDenied",
        "RBACForbidden",
        "LimitRangeViolation",
    ]

    requires = {
        "objects": ["namespace"],
    }

    supported_phases = {
        "Pending",
        "Running",
        "Succeeded",
        "Failed",
        "Unknown",
    }

    TERMINATION_MESSAGES = (
        "unable to create new content in namespace",
        "namespace is being terminated",
        "because it is being terminated",
        "forbidden while the namespace is terminating",
        "unable to create resource in namespace",
    )

    CONTROLLER_REASONS = {
        "FailedCreate",
        "FailedUpdate",
        "FailedSync",
    }

    def _namespace_name(
        self,
        pod: dict[str, Any],
    ) -> str:
        return pod.get("metadata", {}).get("namespace", "default")

    def _candidate_namespace(
        self,
        pod: dict[str, Any],
        namespace_objs: dict[str, dict[str, Any]],
    ) -> tuple[str, dict[str, Any]] | None:
        namespace_name = self._namespace_name(pod)

        if namespace_name in namespace_objs:
            return namespace_name, namespace_objs[namespace_name]

        if len(namespace_objs) == 1:
            return next(iter(namespace_objs.items()))

        return None

    def _namespace_terminating(
        self,
        namespace: dict[str, Any],
    ) -> bool:
        metadata = namespace.get("metadata", {})
        status = namespace.get("status", {})

        if metadata.get("deletionTimestamp"):
            return True

        phase = str(status.get("phase", "")).lower()

        return phase == "terminating"

    def _event_reason(
        self,
        event: dict[str, Any],
    ) -> str:
        return str(event.get("reason", ""))

    def _event_message(
        self,
        event: dict[str, Any],
    ) -> str:
        return str(event.get("message", ""))

    def _event_text(
        self,
        event: dict[str, Any],
    ) -> str:
        return (f"{self._event_reason(event)} " f"{self._event_message(event)}").lower()

    def _event_targets_namespace(
        self,
        event: dict[str, Any],
        namespace_name: str,
    ) -> bool:
        involved = event.get("involvedObject", {})

        if isinstance(involved, dict):
            if (
                str(involved.get("kind", "")).lower() == "namespace"
                and involved.get("name") == namespace_name
            ):
                return True

            if involved.get("namespace") == namespace_name:
                return True

        return namespace_name.lower() in self._event_text(event)

    def _termination_event(
        self,
        events,
        namespace_name: str,
    ) -> dict[str, Any] | None:
        for event in events or []:
            if not self._event_targets_namespace(
                event,
                namespace_name,
            ):
                continue

            text = self._event_text(event)

            if any(marker in text for marker in self.TERMINATION_MESSAGES):
                return event

        return None

    def _controller_failure_event(
        self,
        events,
        namespace_name: str,
    ) -> dict[str, Any] | None:
        for event in events or []:
            reason = self._event_reason(event)

            if reason not in self.CONTROLLER_REASONS:
                continue

            text = self._event_text(event)

            if namespace_name.lower() not in text:
                continue

            if any(marker in text for marker in self.TERMINATION_MESSAGES):
                return event

        return None

    def _correlation(
        self,
        pod: dict[str, Any],
        events,
        namespace_name: str,
        namespace: dict[str, Any],
    ) -> dict[str, Any] | None:
        if not self._namespace_terminating(namespace):
            return None

        termination_event = self._termination_event(
            events,
            namespace_name,
        )

        if termination_event:
            return {
                "event": termination_event,
                "source": "apiserver",
            }

        controller_event = self._controller_failure_event(
            events,
            namespace_name,
        )

        if controller_event:
            return {
                "event": controller_event,
                "source": "controller",
            }

        metadata = namespace.get("metadata", {})

        if metadata.get("deletionTimestamp"):
            return {
                "event": None,
                "source": "namespace_state",
            }

        return None

    def matches(self, pod, events, context) -> bool:
        namespace_objs = context.get("objects", {}).get("namespace", {})

        if not namespace_objs:
            return False

        candidate = self._candidate_namespace(
            pod,
            namespace_objs,
        )

        if candidate is None:
            return False

        namespace_name, namespace = candidate

        return (
            self._correlation(
                pod,
                events,
                namespace_name,
                namespace,
            )
            is not None
        )

    def explain(self, pod, events, context):
        namespace_objs = context.get("objects", {}).get("namespace", {})

        candidate = self._candidate_namespace(
            pod,
            namespace_objs,
        )

        if candidate is None:
            raise ValueError("NamespaceTerminatingBlocksPod requires namespace object")

        namespace_name, namespace = candidate

        correlation = self._correlation(
            pod,
            events,
            namespace_name,
            namespace,
        )

        if correlation is None:
            raise ValueError(
                "NamespaceTerminatingBlocksPod explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<unknown>")

        metadata = namespace.get("metadata", {})

        deletion_timestamp = str(
            metadata.get(
                "deletionTimestamp",
                "unknown",
            )
        )

        phase = str(namespace.get("status", {}).get("phase", "Unknown"))

        event_message = ""

        if correlation["event"] is not None:
            event_message = str(correlation["event"].get("message", "")).strip()

        chain = CausalChain(
            causes=[
                Cause(
                    code="NAMESPACE_DELETION_STARTED",
                    message=("Namespace deletion has been initiated"),
                    role="lifecycle_root",
                ),
                Cause(
                    code="NAMESPACE_TERMINATING",
                    message=("The namespace remains in Terminating state"),
                    role="api_machinery",
                    blocking=True,
                ),
                Cause(
                    code="RESOURCE_CREATION_BLOCKED",
                    message=(
                        "API server rejects creation or update of "
                        "resources inside the terminating namespace"
                    ),
                    role="admission_gate",
                ),
                Cause(
                    code="POD_OPERATION_FAILED",
                    message=(
                        "Pod creation or reconciliation cannot proceed "
                        "while namespace termination is in progress"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": (
                f"Namespace {namespace_name} is terminating, "
                "preventing pod creation or updates"
            ),
            "confidence": 0.99,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Namespace phase={phase}",
                f"Namespace deletionTimestamp={deletion_timestamp}",
                "Namespace is undergoing deletion",
                "API machinery blocks new resource creation inside terminating namespaces",
                *([event_message] if event_message else []),
            ],
            "object_evidence": {
                f"namespace:{namespace_name}": [
                    f"phase={phase}",
                    f"deletionTimestamp={deletion_timestamp}",
                    "Namespace lifecycle is terminating",
                ],
                f"pod:{pod_name}": [
                    "Pod operations are blocked by namespace termination",
                    *([event_message] if event_message else []),
                ],
            },
            "likely_causes": [
                "Namespace deletion was intentionally requested",
                "Controllers are still removing namespaced resources",
                "Namespace contains resources with finalizers preventing immediate deletion",
                "An operator or automation is recreating pods while the namespace is being deleted",
                "Deployment, StatefulSet, Job, or ReplicaSet reconciliation is occurring during namespace shutdown",
            ],
            "suggested_checks": [
                f"kubectl get namespace {namespace_name} -o yaml",
                f"kubectl describe namespace {namespace_name}",
                (f"kubectl get all -n {namespace_name}"),
                (
                    f"kubectl api-resources --verbs=list "
                    f"--namespaced -o name | "
                    f"xargs -n 1 kubectl get -n {namespace_name}"
                ),
                "Inspect namespace finalizers",
                "Determine which resources are preventing namespace deletion from completing",
            ],
        }
