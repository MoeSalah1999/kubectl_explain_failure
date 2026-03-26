from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class CSIProvisioningFailedRule(FailureRule):
    """
    Detects dynamic provisioning failures for CSI-backed PVCs.

    Real-world behavior:
    - `ExternalProvisioning` is informational and means Kubernetes is still
      waiting for an external provisioner.
    - `ProvisioningFailed` is the actual failure signal.
    - CSI-specific context comes from either the StorageClass provisioner or
      CreateVolume / gRPC style error text.
    """

    name = "CSIProvisioningFailed"
    category = "PersistentVolumeClaim"
    priority = 95
    deterministic = True

    blocks = [
        "PVCNotBound",
        "DynamicProvisioningTimeout",
    ]

    phases = ["Pending"]

    requires = {
        "context": ["timeline"],
        "objects": ["pvc"],
        "optional_objects": ["storageclass"],
    }

    def _occurrences(self, event: dict) -> int:
        count = event.get("count", 1)
        try:
            return max(int(count), 1)
        except Exception:
            return 1

    def _referenced_or_all_pvcs(self, pod: dict, context: dict) -> dict[str, dict]:
        pvc_objects = context.get("objects", {}).get("pvc", {})
        referenced = {}

        for volume in pod.get("spec", {}).get("volumes", []) or []:
            claim = volume.get("persistentVolumeClaim") or {}
            claim_name = claim.get("claimName")
            if claim_name and claim_name in pvc_objects:
                referenced[claim_name] = pvc_objects[claim_name]

        return referenced or pvc_objects

    def _pending_pvcs(self, pod: dict, context: dict) -> dict[str, dict]:
        return {
            name: pvc
            for name, pvc in self._referenced_or_all_pvcs(pod, context).items()
            if pvc.get("status", {}).get("phase") != "Bound"
        }

    def _is_csi_storageclass(self, provisioner: str | None) -> bool:
        if provisioner is None:
            return False
        return "csi" in provisioner.lower()

    def _matching_failure_events(self, timeline) -> list[dict]:
        return [
            event
            for event in timeline.raw_events
            if event.get("reason") == "ProvisioningFailed"
        ]

    def _has_csi_context(
        self,
        pod: dict,
        context: dict,
        failure_events: list[dict],
    ) -> bool:
        storageclasses = context.get("objects", {}).get("storageclass", {})

        for pvc in self._pending_pvcs(pod, context).values():
            sc_name = pvc.get("spec", {}).get("storageClassName")
            if not sc_name:
                continue

            storageclass = storageclasses.get(sc_name, {})
            if self._is_csi_storageclass(storageclass.get("provisioner")):
                return True

        for event in failure_events:
            message = str(event.get("message", "")).lower()
            if any(
                marker in message for marker in ("createvolume", "rpc error", "csi")
            ):
                return True

        return False

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        if not timeline:
            return False

        pending_pvcs = self._pending_pvcs(pod, context)
        if not pending_pvcs:
            return False

        failure_events = self._matching_failure_events(timeline)
        if not failure_events:
            return False

        if timeline.count(reason="ProvisioningSucceeded") > 0:
            return False

        if not self._has_csi_context(pod, context, failure_events):
            return False

        total_failures = sum(self._occurrences(event) for event in failure_events)
        duration = timeline.duration_between(
            lambda e: e.get("reason") in {"ProvisioningFailed", "ExternalProvisioning"}
        )

        if total_failures < 2 and duration < 60:
            return False

        return True

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name", "<unknown>")
        timeline = context.get("timeline")
        pvc_names = sorted(self._pending_pvcs(pod, context)) or ["<unknown>"]

        dominant_msg = None
        if timeline:
            messages = [
                (event.get("message") or "")
                for event in timeline.raw_events
                if event.get("reason") == "ProvisioningFailed"
                for _ in range(self._occurrences(event))
            ]
            if messages:
                dominant_msg = max(set(messages), key=messages.count)

        chain = CausalChain(
            causes=[
                Cause(
                    code="CSI_PROVISIONING_FAILURE",
                    message="CSI driver failed to provision a volume",
                    role="volume_root",
                    blocking=True,
                ),
                Cause(
                    code="PVC_UNBOUND",
                    message="PersistentVolumeClaim remains unbound due to provisioning failure",
                    role="storage_intermediate",
                ),
                Cause(
                    code="POD_VOLUME_BLOCKED",
                    message="Pod cannot start because required volume is not available",
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": "PVC cannot be provisioned due to CSI driver or storage backend failure",
            "confidence": 0.96,
            "causes": chain,
            "evidence": [
                "PVC remains Pending while ProvisioningFailed events continue",
                "Provisioning failures align with CSI provisioner or CreateVolume behavior",
                "ExternalProvisioning alone is not treated as a failure signal",
                *(
                    ["Dominant provisioning error: " + dominant_msg]
                    if dominant_msg
                    else []
                ),
            ],
            "likely_causes": [
                "CSI driver is not running or misconfigured",
                "StorageClass parameters are invalid",
                "Backend storage system rejected volume creation",
                "Insufficient storage capacity or quota exceeded",
                "Permission or authentication failure in CSI provisioner",
            ],
            "suggested_checks": [
                *[f"kubectl describe pvc {pvc_name}" for pvc_name in pvc_names],
                f"kubectl describe pod {pod_name}",
                "kubectl get storageclass",
                "kubectl get events --sort-by=.lastTimestamp",
                "kubectl get pods -n kube-system",
                "Inspect CSI provisioner logs",
            ],
            "blocking": True,
            "object_evidence": {
                **{
                    f"pvc:{pvc_name}": [
                        "PVC remains Pending while CSI provisioning fails"
                    ]
                    for pvc_name in pvc_names
                },
                f"pod:{pod_name}": [
                    "Pod blocked waiting for dynamically provisioned volume"
                ],
            },
        }
