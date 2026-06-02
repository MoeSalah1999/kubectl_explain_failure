from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CRDVersionRemovedOrUnservedRule(FailureRule):
    """
    Detects workloads or controllers depending on a CRD API version
    that is no longer served by the cluster.

    Real-world interpretation:
    - cluster upgrade removed a deprecated CRD version
    - CRD spec.versions[*].served=false
    - operators/controllers still request removed versions
    - manifests still reference removed apiVersions
    - discovery succeeds for CRD but requested version is unavailable

    Common examples:
    - apiextensions.k8s.io/v1beta1 removed
    - cert-manager.io/v1alpha2 removed
    - monitoring.coreos.com/v1beta1 removed
    - custom operator still using deprecated API versions

    These failures frequently appear after:
    - Kubernetes minor-version upgrades
    - operator upgrades
    - CRD migration drift
    - GitOps rollback inconsistencies
    """

    name = "CRDVersionRemovedOrUnserved"
    category = "APIMachinery"
    priority = 91
    deterministic = True

    supported_phases = {
        "Pending",
        "Running",
        "Succeeded",
        "Failed",
        "Unknown",
    }

    requires = {
        "objects": ["crd"],
    }

    blocks = [
        "ReplicaSetCreateFailure",
        "DeploymentProgressDeadlineExceeded",
        "StatefulSetUpdateBlocked",
        "ControllerManagerUnavailable",
        "AdmissionWebhookDenied",
        "APIServiceUnavailable",
    ]

    VERSION_REMOVED_MARKERS = (
        "no matches for kind",
        "could not find the requested resource",
        "the server could not find the requested resource",
        "unable to recognize",
        "failed to list",
        "failed to watch",
        "unknown api version",
        "unsupported version",
        "resource not found",
        "is not served",
        "has no served version",
    )

    CONTROLLER_REASONS = {
        "FailedCreate",
        "FailedUpdate",
        "FailedSync",
        "FailedReconcile",
        "SyncError",
    }

    CACHE_KEY = "_crd_version_removed_candidate"

    def _event_message(
        self,
        event: dict[str, Any],
    ) -> str:
        return str(event.get("message", ""))

    def _event_text(
        self,
        event: dict[str, Any],
    ) -> str:
        reason = str(event.get("reason", ""))
        message = self._event_message(event)

        return f"{reason} {message}".lower()

    def _event_reason(
        self,
        event: dict[str, Any],
    ) -> str:
        return str(event.get("reason", ""))

    def _served_versions(
        self,
        crd: dict[str, Any],
    ) -> set[str]:
        versions = set()

        for version in crd.get("spec", {}).get("versions", []) or []:
            if not isinstance(version, dict):
                continue

            if version.get("served") is True:
                name = version.get("name")

                if name:
                    versions.add(str(name))

        return versions

    def _all_versions(
        self,
        crd: dict[str, Any],
    ) -> set[str]:
        versions = set()

        for version in crd.get("spec", {}).get("versions", []) or []:
            if not isinstance(version, dict):
                continue

            name = version.get("name")

            if name:
                versions.add(str(name))

        return versions

    def _crd_group(
        self,
        crd: dict[str, Any],
    ) -> str:
        return str(crd.get("spec", {}).get("group", ""))

    def _crd_name(
        self,
        crd: dict[str, Any],
    ) -> str:
        return str(crd.get("metadata", {}).get("name", "<unknown>"))

    def _event_mentions_group(
        self,
        event: dict[str, Any],
        group: str,
    ) -> bool:
        if not group:
            return False

        return group.lower() in self._event_text(event)

    def _removed_version_from_event(
        self,
        event: dict[str, Any],
        versions: set[str],
    ) -> str | None:
        text = self._event_text(event)

        for version in sorted(
            versions,
            key=len,
            reverse=True,
        ):
            if version.lower() in text:
                return version

        return None

    def _unserved_version_candidate(
        self,
        crd: dict[str, Any],
        events,
    ) -> dict[str, Any] | None:
        served_versions = self._served_versions(crd)
        all_versions = self._all_versions(crd)

        removed_versions = all_versions - served_versions

        if not removed_versions:
            return None

        group = self._crd_group(crd)

        for event in events or []:
            reason = self._event_reason(event)

            if reason not in self.CONTROLLER_REASONS and reason:
                continue

            text = self._event_text(event)

            if not any(marker in text for marker in self.VERSION_REMOVED_MARKERS):
                continue

            if not self._event_mentions_group(
                event,
                group,
            ):
                continue

            removed_version = self._removed_version_from_event(
                event,
                removed_versions,
            )

            if removed_version is None:
                continue

            return {
                "event": event,
                "group": group,
                "removed_version": removed_version,
                "served_versions": sorted(served_versions),
            }

        return None

    def _candidate(
        self,
        events,
        context,
    ) -> dict[str, Any] | None:
        crds = context.get("objects", {}).get("crd", {})

        for crd in crds.values():
            if not isinstance(crd, dict):
                continue

            candidate = self._unserved_version_candidate(
                crd,
                events,
            )

            if candidate is not None:
                candidate["crd"] = crd
                return candidate

        return None

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(
            events,
            context,
        )

        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False

        context[self.CACHE_KEY] = candidate

        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(events, context)

        if candidate is None:
            raise ValueError(
                "CRDVersionRemovedOrUnserved explain() called without match"
            )

        crd = candidate["crd"]

        crd_name = self._crd_name(crd)

        group = candidate["group"]

        removed_version = candidate["removed_version"]

        served_versions = candidate["served_versions"]

        event = candidate["event"]

        event_message = str(event.get("message", "")).strip()

        pod_name = pod.get("metadata", {}).get(
            "name",
            "<unknown>",
        )

        chain = CausalChain(
            causes=[
                Cause(
                    code="CRD_API_VERSION_DRIFT",
                    message=(
                        "Cluster components depend on a deprecated "
                        "or removed CRD API version"
                    ),
                    role="upgrade_root",
                ),
                Cause(
                    code="CRD_VERSION_NOT_SERVED",
                    message=(
                        "The requested CRD API version is no longer "
                        "served by the Kubernetes API"
                    ),
                    role="api_machinery",
                    blocking=True,
                ),
                Cause(
                    code="DISCOVERY_OR_RECONCILIATION_FAILURE",
                    message=(
                        "Controllers or workloads cannot successfully "
                        "discover or reconcile the custom resource"
                    ),
                    role="controller_failure",
                ),
                Cause(
                    code="WORKLOAD_DEGRADED",
                    message=(
                        "Dependent workloads fail because the "
                        "required CRD API version is unavailable"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        confidence = 0.95

        if removed_version and served_versions:
            confidence = 0.98

        return {
            "root_cause": (
                f"CRD API version " f"{group}/{removed_version} " "is no longer served"
            ),
            "confidence": confidence,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"CRD={crd_name}",
                f"CRD group={group}",
                (f"Removed or unserved version=" f"{removed_version}"),
                ("Currently served versions=" f"{', '.join(served_versions)}"),
                (
                    "Controllers or workloads are still "
                    "requesting the removed version"
                ),
                event_message,
            ],
            "object_evidence": {
                f"crd:{crd_name}": [
                    (f"Version {removed_version} " "is not served"),
                    ("Served versions: " f"{', '.join(served_versions)}"),
                ],
                f"pod:{pod_name}": [
                    ("Pod or controller depends on " "a removed CRD API version"),
                    event_message,
                ],
            },
            "likely_causes": [
                "Cluster upgrade removed deprecated CRD API versions",
                "Operator upgrade changed served CRD versions",
                "Controllers still reference legacy apiVersion fields",
                "GitOps manifests contain deprecated CRD versions",
                "Helm charts reference removed CRD APIs",
                "CRD migration was partially completed",
                "Conversion webhook migration was incomplete",
            ],
            "suggested_checks": [
                f"kubectl get crd {crd_name} -o yaml",
                ("kubectl api-resources " "--api-group " f"{group}"),
                ("kubectl explain " f"--api-version={group}/{removed_version}"),
                (
                    "Search manifests for deprecated "
                    f"apiVersion={group}/{removed_version}"
                ),
                "Inspect operator and controller logs",
                "Verify CRD spec.versions[*].served fields",
                "Review Kubernetes and operator upgrade notes",
            ],
        }
