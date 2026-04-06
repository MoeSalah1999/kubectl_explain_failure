from __future__ import annotations

from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class StatefulSetVolumeClaimTemplateMissingRule(FailureRule):
    """
    Detects StatefulSets whose Pods reference ordinal-style PVC names that would
    normally be generated from volumeClaimTemplates, but the corresponding claim
    template is missing from the StatefulSet spec.
    """

    name = "StatefulSetVolumeClaimTemplateMissing"
    category = "Controller"
    priority = 61
    deterministic = True
    phases = ["Pending", "Running"]
    requires = {
        "pod": True,
        "objects": ["statefulset"],
        "context": ["timeline"],
        "optional_objects": ["pvc"],
    }
    blocks = [
        "FailedMount",
        "FailedScheduling",
        "PendingUnschedulable",
        "PVCNotBound",
        "PVCMountFailed",
        "PVCMountFailure",
        "RootCauseAmbiguity",
        "StatefulSetUpdateBlocked",
    ]

    WINDOW_MINUTES = 20
    STORAGE_MARKERS = (
        "persistentvolumeclaim",
        "unbound immediate persistentvolumeclaims",
        "failedmount",
        "mountvolume.setup failed",
        "not found",
    )
    PREFERRED_SIGNAL_MARKERS = (
        "mountvolume.setup failed",
        "persistentvolumeclaim",
        "not found",
    )

    def _owning_statefulset_name(self, pod: dict[str, Any]) -> str | None:
        for owner in pod.get("metadata", {}).get("ownerReferences", []) or []:
            if str(owner.get("kind", "")).lower() == "statefulset":
                return str(owner.get("name", ""))
        return None

    def _find_statefulset(
        self,
        sts_name: str,
        namespace: str,
        objects: dict[str, Any],
    ) -> dict[str, Any] | None:
        direct = objects.get("statefulset", {}).get(sts_name)
        if isinstance(direct, dict):
            if direct.get("metadata", {}).get("namespace", "default") == namespace:
                return direct
        for obj in objects.get("statefulset", {}).values():
            if not isinstance(obj, dict):
                continue
            metadata = obj.get("metadata", {})
            if metadata.get("name") != sts_name:
                continue
            if metadata.get("namespace", "default") != namespace:
                continue
            return obj
        return None

    def _template_names(self, sts: dict[str, Any]) -> set[str]:
        names = set()
        for template in sts.get("spec", {}).get("volumeClaimTemplates", []) or []:
            name = template.get("metadata", {}).get("name")
            if name:
                names.add(str(name))
        return names

    def _pod_ordinal(self, pod_name: str, sts_name: str) -> int | None:
        prefix = f"{sts_name}-"
        if not pod_name.startswith(prefix):
            return None
        suffix = pod_name[len(prefix) :]
        try:
            return int(suffix)
        except ValueError:
            return None

    def _ordinal_claim_candidate(
        self,
        claim_name: str,
        sts_name: str,
        ordinal: int,
    ) -> str | None:
        suffix = f"-{sts_name}-{ordinal}"
        if not claim_name.endswith(suffix):
            return None
        template_name = claim_name[: -len(suffix)]
        return template_name or None

    def _missing_template_candidate(
        self,
        pod: dict[str, Any],
        sts: dict[str, Any],
        objects: dict[str, Any],
    ) -> dict[str, str] | None:
        pod_name = pod.get("metadata", {}).get("name", "")
        sts_name = sts.get("metadata", {}).get("name", "")
        ordinal = self._pod_ordinal(pod_name, sts_name)
        if ordinal is None:
            return None

        template_names = self._template_names(sts)
        pvc_objects = objects.get("pvc", {})

        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim = volume.get("persistentVolumeClaim") or {}
            claim_name = claim.get("claimName")
            if not claim_name:
                continue

            template_name = self._ordinal_claim_candidate(
                str(claim_name), sts_name, ordinal
            )
            if template_name is None:
                continue
            if template_name in template_names:
                continue
            if claim_name in pvc_objects:
                continue

            return {
                "claim_name": str(claim_name),
                "template_name": template_name,
                "volume_name": str(volume.get("name", template_name)),
            }

        return None

    def _recent_storage_signal(
        self,
        timeline: Timeline,
        pod_name: str,
        claim_name: str,
    ) -> str | None:
        best_message = None
        best_score = -1

        for event in timeline.events_within_window(self.WINDOW_MINUTES):
            message = str(event.get("message", "")).lower()
            if pod_name.lower() not in message and claim_name.lower() not in message:
                if not any(marker in message for marker in self.STORAGE_MARKERS):
                    continue
            if not any(marker in message for marker in self.STORAGE_MARKERS):
                continue

            score = 0
            if str(event.get("reason", "")).lower() == "failedmount":
                score += 10
            score += sum(
                1 for marker in self.PREFERRED_SIGNAL_MARKERS if marker in message
            )

            if score > best_score:
                best_score = score
                best_message = str(event.get("message", ""))

        return best_message

    def _candidate(
        self, pod: dict[str, Any], context: dict[str, Any]
    ) -> dict[str, str] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        objects = context.get("objects", {})
        sts_name = self._owning_statefulset_name(pod)
        if not sts_name:
            return None

        namespace = pod.get("metadata", {}).get("namespace", "default")
        sts = self._find_statefulset(sts_name, namespace, objects)
        if not sts:
            return None

        missing = self._missing_template_candidate(pod, sts, objects)
        if missing is None:
            return None

        recent_signal = self._recent_storage_signal(
            timeline,
            str(pod.get("metadata", {}).get("name", "")),
            missing["claim_name"],
        )
        if recent_signal is None:
            return None

        return {
            "sts_name": sts_name,
            "claim_name": missing["claim_name"],
            "template_name": missing["template_name"],
            "volume_name": missing["volume_name"],
            "recent_signal": recent_signal,
        }

    def matches(self, pod, events, context) -> bool:
        return self._candidate(pod, context) is not None

    def explain(self, pod, events, context):
        candidate = self._candidate(pod, context)
        if candidate is None:
            raise ValueError(
                "StatefulSetVolumeClaimTemplateMissing explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        sts_name = candidate["sts_name"]
        claim_name = candidate["claim_name"]
        template_name = candidate["template_name"]

        chain = CausalChain(
            causes=[
                Cause(
                    code="STATEFULSET_STORAGE_IDENTITY_EXPECTED",
                    message=f"StatefulSet '{sts_name}' is expected to provide per-pod storage identities across ordinals",
                    role="controller_context",
                ),
                Cause(
                    code="VOLUMECLAIMTEMPLATE_MISSING",
                    message=f"StatefulSet '{sts_name}' is missing volumeClaimTemplate '{template_name}' required to generate PVC '{claim_name}'",
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="STATEFULSET_PVC_NOT_MATERIALIZED",
                    message="The StatefulSet controller cannot materialize the expected per-ordinal PVC for the Pod",
                    role="controller_intermediate",
                ),
                Cause(
                    code="STATEFULSET_POD_STORAGE_BLOCKED",
                    message="Pod startup is blocked because the expected StatefulSet storage claim does not exist",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "StatefulSet rollout references a missing volumeClaimTemplate",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": [
                f"Pod {pod_name} is owned by StatefulSet {sts_name}",
                f"Pod references ordinal PVC {claim_name} for volume {candidate['volume_name']}",
                f"StatefulSet {sts_name} has no volumeClaimTemplate named {template_name}",
                f"Recent storage signal: {candidate['recent_signal']}",
            ],
            "object_evidence": {
                f"statefulset:{sts_name}": [
                    f"Missing volumeClaimTemplate {template_name}"
                ],
                f"pod:{pod_name}": [
                    f"Volume {candidate['volume_name']} references PVC {claim_name}"
                ],
            },
            "likely_causes": [
                "The StatefulSet spec references an ordinal-style PVC name but the matching volumeClaimTemplate was never defined",
                "A copied or hand-edited StatefulSet manifest mixes explicit claim names with template-based storage semantics",
                "A rollout introduced storage naming drift between Pod volumes and StatefulSet volumeClaimTemplates",
            ],
            "suggested_checks": [
                f"kubectl describe statefulset {sts_name}",
                f"kubectl describe pod {pod_name}",
                "Compare StatefulSet spec.volumeClaimTemplates with Pod volume claim names and ordinal naming",
                "Use volumeClaimTemplates for per-replica PVC generation instead of hardcoding ordinal claim names",
            ],
        }
