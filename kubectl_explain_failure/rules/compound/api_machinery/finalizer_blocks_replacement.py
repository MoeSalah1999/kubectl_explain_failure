from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class FinalizerBlocksReplacementRule(FailureRule):
    """
    Detects resources stuck in deletion because finalizers prevent cleanup,
    blocking pod/PVC/workload replacement and rollout progression.

    Real-world interpretation:
    - Pod stuck Terminating due to finalizer
    - PVC deletion blocked by CSI/external-provisioner finalizer
    - StatefulSet replacement blocked waiting for PVC cleanup
    - Deployment rollout stalls because old ReplicaSet pods never disappear
    - Operator-managed resources stuck pending finalization
    - Namespace-scoped garbage collection cannot complete

    Common production symptoms:
    - old pods remain forever in Terminating
    - replacements never appear
    - StatefulSet ordinal rollout blocked
    - PVC recreation impossible
    - Deployment exceeds progress deadline
    """

    name = "FinalizerBlocksReplacement"
    category = "Compound"
    priority = 88
    deterministic = True

    supported_phases = {
        "Pending",
        "Running",
        "Failed",
        "Unknown",
    }

    requires = {
        "pod": True,
        "context": ["timeline"],
        "optional_objects": [
            "pod",
            "pvc",
            "deployment",
            "replicaset",
            "statefulset",
            "daemonset",
        ],
    }

    blocks = [
        "DeploymentProgressDeadlineExceeded",
        "ReplicaSetUnavailable",
        "StatefulSetUpdateBlocked",
        "PVCMountFailed",
        "PVCPendingTooLong",
        "VolumeAttachFailed",
    ]

    CACHE_KEY = "_finalizer_blocks_replacement_candidate"

    STUCK_MINUTES = 10

    FINALIZER_EVENT_MARKERS = (
        "waiting for finalizers",
        "object is being deleted",
        "cannot remove finalizer",
        "failed to remove finalizer",
        "resource is terminating",
        "foreground deletion",
        "waiting for deletion",
        "timed out waiting for deletion",
    )

    CONTROLLER_REASONS = {
        "FailedCreate",
        "FailedDelete",
        "FailedUpdate",
        "FailedScheduling",
        "ProgressDeadlineExceeded",
        "FailedMount",
    }

    def _parse_ts(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None

        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_ts(
        self,
        event: dict[str, Any],
    ) -> datetime | None:
        return (
            self._parse_ts(event.get("lastTimestamp"))
            or self._parse_ts(event.get("eventTime"))
            or self._parse_ts(event.get("firstTimestamp"))
            or self._parse_ts(event.get("timestamp"))
        )

    def _message(
        self,
        event: dict[str, Any],
    ) -> str:
        return str(event.get("message", "")).strip()

    def _event_text(
        self,
        event: dict[str, Any],
    ) -> str:
        reason = str(event.get("reason", ""))
        message = self._message(event)

        return f"{reason} {message}".lower()

    def _namespace(
        self,
        obj: dict[str, Any],
    ) -> str:
        return str(
            obj.get("metadata", {}).get(
                "namespace",
                "default",
            )
        )

    def _find_named_object(
        self,
        objects: dict[str, Any],
        kind: str,
        name: str,
        namespace: str,
    ) -> dict[str, Any] | None:
        direct = objects.get(kind, {}).get(name)

        if isinstance(direct, dict) and self._namespace(direct) == namespace:
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

    def _owner_ref(
        self,
        obj: dict[str, Any],
        kind: str,
    ) -> str | None:
        for ref in (
            obj.get("metadata", {}).get(
                "ownerReferences",
                [],
            )
            or []
        ):
            if str(ref.get("kind", "")).lower() == kind.lower() and ref.get("name"):
                return str(ref["name"])

        return None

    def _deletion_timestamp(
        self,
        obj: dict[str, Any],
    ) -> datetime | None:
        return self._parse_ts(obj.get("metadata", {}).get("deletionTimestamp"))

    def _finalizers(
        self,
        obj: dict[str, Any],
    ) -> list[str]:
        finalizers = obj.get("metadata", {}).get("finalizers", []) or []

        return [str(value) for value in finalizers if value]

    def _stuck_terminating(
        self,
        obj: dict[str, Any],
        *,
        reference_time: datetime,
    ) -> bool:
        deletion_ts = self._deletion_timestamp(obj)

        if deletion_ts is None:
            return False

        finalizers = self._finalizers(obj)

        if not finalizers:
            return False

        age = reference_time - deletion_ts

        return age >= timedelta(minutes=self.STUCK_MINUTES)

    def _timeline_reference_time(
        self,
        timeline: Timeline,
    ) -> datetime:
        latest: datetime | None = None

        for event in timeline.events:
            ts = self._event_ts(event)

            if ts is None:
                continue

            if latest is None or ts > latest:
                latest = ts

        return latest or datetime.now(timezone.utc)

    def _event_targets_object(
        self,
        event: dict[str, Any],
        *,
        kind: str,
        name: str,
        namespace: str,
    ) -> bool:
        involved = (
            event.get(
                "involvedObject",
                {},
            )
            or {}
        )

        if not isinstance(involved, dict):
            return False

        involved_kind = str(involved.get("kind", "")).lower()

        involved_name = str(involved.get("name", ""))

        involved_namespace = str(
            involved.get(
                "namespace",
                namespace,
            )
        )

        return (
            involved_kind == kind.lower()
            and involved_name == name
            and involved_namespace == namespace
        )

    def _matching_events(
        self,
        timeline: Timeline,
        *,
        kind: str,
        name: str,
        namespace: str,
    ) -> list[dict[str, Any]]:
        results = []

        for event in timeline.events_within_window(60):
            if not self._event_targets_object(
                event,
                kind=kind,
                name=name,
                namespace=namespace,
            ):
                continue

            text = self._event_text(event)

            reason = str(event.get("reason", ""))

            if reason in self.CONTROLLER_REASONS or any(
                marker in text for marker in self.FINALIZER_EVENT_MARKERS
            ):
                results.append(event)

        return results

    def _deployment_rollout_stalled(
        self,
        deployment: dict[str, Any],
    ) -> bool:
        status = (
            deployment.get(
                "status",
                {},
            )
            or {}
        )

        desired = int(
            status.get(
                "replicas",
                deployment.get(
                    "spec",
                    {},
                ).get("replicas", 0),
            )
            or 0
        )

        updated = int(
            status.get(
                "updatedReplicas",
                0,
            )
            or 0
        )

        available = int(
            status.get(
                "availableReplicas",
                0,
            )
            or 0
        )

        progressing = any(
            (
                condition.get("type") == "Progressing"
                and condition.get("status") == "False"
            )
            for condition in (
                status.get(
                    "conditions",
                    [],
                )
                or []
            )
        )

        return desired > 0 and (updated < desired or available < desired or progressing)

    def _candidate(
        self,
        pod: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")

        if not isinstance(timeline, Timeline):
            return None

        objects = context.get(
            "objects",
            {},
        )

        reference_time = self._timeline_reference_time(timeline)

        namespace = self._namespace(pod)

        pods = objects.get("pod", {}) or {}

        for pod_obj in pods.values():
            if not isinstance(pod_obj, dict):
                continue

            if self._namespace(pod_obj) != namespace:
                continue

            if not self._stuck_terminating(
                pod_obj,
                reference_time=reference_time,
            ):
                continue

            finalizers = self._finalizers(pod_obj)

            pod_name = str(
                pod_obj.get("metadata", {}).get(
                    "name",
                    "<unknown>",
                )
            )

            events = self._matching_events(
                timeline,
                kind="Pod",
                name=pod_name,
                namespace=namespace,
            )

            workload_symptom = None

            rs_name = self._owner_ref(
                pod_obj,
                "ReplicaSet",
            )

            if rs_name:
                rs = self._find_named_object(
                    objects,
                    "replicaset",
                    rs_name,
                    namespace,
                )

                if rs:
                    deployment_name = self._owner_ref(
                        rs,
                        "Deployment",
                    )

                    if deployment_name:
                        deployment = self._find_named_object(
                            objects,
                            "deployment",
                            deployment_name,
                            namespace,
                        )

                        if deployment and self._deployment_rollout_stalled(deployment):
                            workload_symptom = (
                                f"Deployment '{deployment_name}' "
                                "rollout is stalled while old "
                                "pods remain stuck terminating"
                            )

            return {
                "resource_kind": "Pod",
                "resource_name": pod_name,
                "namespace": namespace,
                "finalizers": finalizers,
                "events": events,
                "workload_symptom": workload_symptom,
                "resource": pod_obj,
            }

        pvcs = objects.get("pvc", {}) or {}

        for pvc_obj in pvcs.values():
            if not isinstance(pvc_obj, dict):
                continue

            if self._namespace(pvc_obj) != namespace:
                continue

            if not self._stuck_terminating(
                pvc_obj,
                reference_time=reference_time,
            ):
                continue

            pvc_name = str(
                pvc_obj.get("metadata", {}).get(
                    "name",
                    "<unknown>",
                )
            )

            events = self._matching_events(
                timeline,
                kind="PersistentVolumeClaim",
                name=pvc_name,
                namespace=namespace,
            )

            return {
                "resource_kind": "PersistentVolumeClaim",
                "resource_name": pvc_name,
                "namespace": namespace,
                "finalizers": self._finalizers(pvc_obj),
                "events": events,
                "workload_symptom": (
                    f"PVC '{pvc_name}' remains "
                    "stuck terminating and may "
                    "block workload replacement"
                ),
                "resource": pvc_obj,
            }

        return None

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(
            pod,
            context,
        )

        if candidate is None:
            context.pop(
                self.CACHE_KEY,
                None,
            )

            return False

        context[self.CACHE_KEY] = candidate

        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(
            pod,
            context,
        )

        if candidate is None:
            raise ValueError(
                "FinalizerBlocksReplacement explain() " "called without match"
            )

        resource_kind = candidate["resource_kind"]

        resource_name = candidate["resource_name"]

        namespace = candidate["namespace"]

        finalizers = candidate["finalizers"]

        workload_symptom = candidate.get("workload_symptom")

        resource = candidate["resource"]

        deletion_ts = str(
            resource.get("metadata", {}).get(
                "deletionTimestamp",
                "<unknown>",
            )
        )

        evidence = [
            (
                f"{resource_kind} "
                f"'{resource_name}' "
                "has a deletionTimestamp but "
                "still contains finalizers"
            ),
            ("Remaining finalizers: " f"{', '.join(finalizers)}"),
            (f"{resource_kind} " "remains stuck in terminating state"),
            (
                "Kubernetes garbage collection "
                "cannot complete until finalizers finish"
            ),
            (f"Deletion timestamp: " f"{deletion_ts}"),
        ]

        object_evidence = {
            (f"{resource_kind.lower()}:" f"{resource_name}"): [
                ("Resource deletion is blocked " "by remaining finalizers"),
                ("Finalizers=" f"{','.join(finalizers)}"),
                (f"deletionTimestamp=" f"{deletion_ts}"),
            ]
        }

        candidate_events = candidate.get("events", [])

        if candidate_events:
            latest = candidate_events[-1]

            latest_message = self._message(latest)

            if latest_message:
                evidence.append(latest_message)

                object_evidence[
                    (f"{resource_kind.lower()}:" f"{resource_name}")
                ].append(latest_message)

        if workload_symptom:
            evidence.append(workload_symptom)

        pod_name = pod.get(
            "metadata",
            {},
        ).get(
            "name",
            "<unknown>",
        )

        object_evidence[f"pod:{pod_name}"] = [
            (
                "Replacement or reconciliation "
                "may be blocked while prior "
                "resources remain terminating"
            )
        ]

        confidence = 0.95

        if candidate_events:
            confidence = 0.98

        chain = CausalChain(
            causes=[
                Cause(
                    code="RESOURCE_DELETION_STARTED",
                    message=(
                        "Kubernetes deletion flow " "has started for the resource"
                    ),
                    role="lifecycle_context",
                ),
                Cause(
                    code="FINALIZER_BLOCKS_DELETION",
                    message=("Resource finalizers prevent " "deletion completion"),
                    role="controller_root",
                    blocking=True,
                ),
                Cause(
                    code="RESOURCE_REPLACEMENT_BLOCKED",
                    message=(
                        "Controllers cannot safely "
                        "replace or recreate the "
                        "resource until deletion "
                        "finishes"
                    ),
                    role="controller_failure",
                ),
                Cause(
                    code="ROLLOUT_OR_RECONCILIATION_STALLED",
                    message=(
                        "Workload rollout or "
                        "reconciliation becomes "
                        "stalled waiting for cleanup"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        ns_flag = f" -n {namespace}" if namespace else ""

        return {
            "root_cause": (
                f"{resource_kind} "
                f"'{resource_name}' "
                "is stuck terminating because "
                "finalizers are blocking deletion"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "CSI driver or storage controller failed to remove PVC finalizers",
                "Custom operator finalizer logic is stuck or crashlooping",
                "External cloud resource cleanup is hanging",
                "Garbage collection dependencies cannot resolve",
                "A controller responsible for finalization is unavailable",
                "The resource contains orphan-protection or foreground-deletion finalizers",
            ],
            "suggested_checks": [
                (
                    f"kubectl get "
                    f"{resource_kind.lower()} "
                    f"{resource_name}"
                    f"{ns_flag} -o yaml"
                ),
                (
                    f"kubectl describe "
                    f"{resource_kind.lower()} "
                    f"{resource_name}"
                    f"{ns_flag}"
                ),
                "Inspect metadata.finalizers",
                "Inspect controller/operator logs responsible for cleanup",
                "Verify external storage or cloud cleanup operations",
                ("Determine whether finalizers " "can be safely removed manually"),
            ],
        }
