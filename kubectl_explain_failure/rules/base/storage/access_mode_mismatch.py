from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import timeline_has_pattern


class AccessModeMismatchRule(FailureRule):
    """
    Detects PersistentVolumeClaim access mode incompatibility with the bound or
    candidate PersistentVolume.

    Signals:
    - PVC requests accessModes incompatible with available PV
    - Kubernetes event indicates volume binding or mount failure
    - PVC remains Pending or volume cannot mount

    Interpretation:
    The PersistentVolumeClaim requests an access mode that no available
    PersistentVolume supports. A common case is a PVC requesting ReadWriteMany
    (RWX) while the available PV only supports ReadWriteOnce (RWO).

    Scope:
    - Storage provisioning layer
    - Deterministic (object compatibility check)
    - Applies to Pods referencing PVC-backed volumes

    Exclusions:
    - Does not include storage backend provisioning failures
    - Does not include already compatible PV/PVC bindings
    """

    name = "AccessModeMismatch"
    category = "PersistentVolumeClaim"
    priority = 45

    requires = {
        "objects": ["pvc", "pv"],
        "context": ["timeline"],
    }

    deterministic = True

    blocks = [
        "PVCNotBound",
        "FailedMount",
    ]

    def matches(self, pod, events, context) -> bool:
        timeline = context.get("timeline")
        objects = context.get("objects", {})

        pvc_objs = objects.get("pvc", {})
        pv_objs = objects.get("pv", {})

        if not pvc_objs or not pv_objs:
            return False

        pvc = next(iter(pvc_objs.values()))
        requested_modes = pvc.get("spec", {}).get("accessModes", [])

        for pv in pv_objs.values():
            supported_modes = pv.get("spec", {}).get("accessModes", [])

            # mismatch if none of the requested modes exist in PV
            if requested_modes and not any(
                m in supported_modes for m in requested_modes
            ):
                # timeline evidence strengthens detection
                if timeline and timeline_has_pattern(
                    timeline,
                    [
                        {"reason": "FailedScheduling"},
                    ],
                ):
                    return True

                # allow deterministic detection even without events
                return True

        return False

    def explain(self, pod, events, context):
        objects = context.get("objects", {})
        pvc_objs = objects.get("pvc", {})
        pv_objs = objects.get("pv", {})

        pvc_name = next(iter(pvc_objs), "<unknown>")
        pv_name = next(iter(pv_objs), "<unknown>")

        pvc = pvc_objs.get(pvc_name, {})
        pv = pv_objs.get(pv_name, {})

        requested_modes = pvc.get("spec", {}).get("accessModes", [])
        supported_modes = pv.get("spec", {}).get("accessModes", [])

        chain = CausalChain(
            causes=[
                Cause(
                    code="PVC_REQUESTS_ACCESS_MODE",
                    message=f"PVC '{pvc_name}' requests access modes {requested_modes}",
                    role="volume_context",
                ),
                Cause(
                    code="PV_ACCESS_MODE_INCOMPATIBLE",
                    message=f"PV '{pv_name}' only supports {supported_modes}",
                    blocking=True,
                    role="volume_root",
                ),
                Cause(
                    code="PVC_CANNOT_BIND",
                    message="PVC cannot bind to a compatible PersistentVolume",
                    role="volume_symptom",
                ),
            ]
        )

        return {
            "root_cause": "PersistentVolume access mode mismatch",
            "confidence": 0.96,
            "causes": chain,
            "evidence": [
                f"PVC {pvc_name} accessModes={requested_modes}",
                f"PV {pv_name} accessModes={supported_modes}",
            ],
            "object_evidence": {
                f"pvc:{pvc_name}": ["Access mode incompatible with available PV"],
                f"pv:{pv_name}": ["Access modes do not satisfy PVC request"],
            },
            "likely_causes": [
                "PVC requests RWX but PV only supports RWO",
                "Incorrect storage class configuration",
                "Cluster storage backend does not support requested access mode",
            ],
            "suggested_checks": [
                f"kubectl get pvc {pvc_name} -o yaml",
                f"kubectl get pv {pv_name} -o yaml",
                "Verify accessModes compatibility between PVC and PV",
            ],
            "blocking": True,
        }
