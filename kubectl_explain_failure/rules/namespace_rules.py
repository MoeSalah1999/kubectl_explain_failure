from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule


class ResourceQuotaExceededRule(FailureRule):
    """
    Detects Pod creation failure due to namespace ResourceQuota exhaustion.
    Signals:
      - Pod.status.reason == FailedCreate
      - OR event.reason == ExceededQuota
      - OR event.message contains 'exceeded quota'
    """

    name = "ResourceQuotaExceeded"
    category = "Admission"
    priority = 26

    requires = {
        "pod": True,
    }

    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        if pod.get("status", {}).get("reason") == "FailedCreate":
            return True

        for e in events or []:
            reason = e.get("reason", "")
            message = (e.get("message") or "").lower()

            if reason == "ExceededQuota":
                return True
            if "exceeded quota" in message:
                return True

        return False

    def explain(self, pod, events, context):
        namespace = pod.get("metadata", {}).get("namespace", "default")
        pod_name = pod.get("metadata", {}).get("name")

        chain = CausalChain(
            causes=[
                Cause(
                    code="RESOURCE_QUOTA_EXCEEDED",
                    message=f"Namespace '{namespace}' exceeded its ResourceQuota",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod creation blocked by ResourceQuota limits",
            "confidence": 0.97,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "Pod.status.reason=FailedCreate or ExceededQuota event detected",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Admission rejected due to ResourceQuota exhaustion"
                ]
            },
            "likely_causes": [
                "CPU requests exceed namespace quota",
                "Memory requests exceed namespace quota",
                "PersistentVolumeClaim storage exceeds quota",
                "Object count quota exceeded",
            ],
            "suggested_checks": [
                f"kubectl describe resourcequota -n {namespace}",
                f"kubectl describe pod {pod_name} -n {namespace}",
            ],
        }


class LimitRangeViolationRule(FailureRule):
    """
    Detects Pod admission failure due to LimitRange violations.
    Signals:
      - event.reason == FailedCreate
      - event.message contains 'limit' or 'exceeds'
    """

    name = "LimitRangeViolation"
    category = "Admission"
    priority = 27

    requires = {
        "pod": True,
    }

    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        for e in events or []:
            if e.get("reason") == "FailedCreate":
                msg = (e.get("message") or "").lower()
                if "limit" in msg or "exceed" in msg:
                    return True
        return False

    def explain(self, pod, events, context):
        namespace = pod.get("metadata", {}).get("namespace", "default")
        pod_name = pod.get("metadata", {}).get("name")

        chain = CausalChain(
            causes=[
                Cause(
                    code="LIMIT_RANGE_VIOLATION",
                    message=f"Pod resource requests violate LimitRange in namespace '{namespace}'",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Pod rejected due to LimitRange violation",
            "confidence": 0.94,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "FailedCreate event referencing resource limits",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Admission rejected due to LimitRange violation"
                ]
            },
            "likely_causes": [
                "CPU request above maximum allowed",
                "Memory request above maximum allowed",
                "Missing required resource requests",
                "Container limits below minimum threshold",
            ],
            "suggested_checks": [
                f"kubectl describe limitrange -n {namespace}",
                f"kubectl get pod {pod_name} -o yaml -n {namespace}",
            ],
        }

    

class RBACForbiddenRule(FailureRule):
    """
    Detects RBAC authorization failures.
    Signals:
      - event.reason == FailedCreate
      - event.message contains 'forbidden'
      - API error message contains 'cannot'
    """

    name = "RBACForbidden"
    category = "Admission"
    priority = 28

    requires = {
        "pod": True,
    }

    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        for e in events or []:
            if e.get("reason") == "FailedCreate":
                msg = (e.get("message") or "").lower()
                if "forbidden" in msg or "cannot" in msg:
                    if "exceed" in msg or "limit" in msg:
                        return False
                    if "user" in msg or "cannot create" in msg:
                        return True


        # Check pod.status.message
        status_msg = (pod.get("status", {}).get("message") or "").lower()
        if "forbidden" in status_msg or "cannot" in status_msg:
            if "limit" in status_msg or "exceed" in status_msg:
                return False
            if "user" in status_msg or "cannot create" in status_msg:
                return True

        return False

    def explain(self, pod, events, context):
        namespace = pod.get("metadata", {}).get("namespace", "default")
        pod_name = pod.get("metadata", {}).get("name")

        chain = CausalChain(
            causes=[
                Cause(
                    code="RBAC_FORBIDDEN",
                    message="Kubernetes API denied action due to RBAC policy",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "RBAC authorization failure prevented Pod creation",
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "FailedCreate event containing 'forbidden'",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Admission rejected due to RBAC authorization failure"
                ]
            },
            "likely_causes": [
                "ServiceAccount lacks required Role/ClusterRole binding",
                "User lacks create permission for resource",
                "Missing verb in Role (e.g., create, get, list)",
            ],
            "suggested_checks": [
                f"kubectl auth can-i create pods -n {namespace}",
                f"kubectl describe rolebinding -n {namespace}",
                "kubectl describe clusterrolebinding",
            ],
        }


class AdmissionWebhookDeniedRule(FailureRule):
    """
    Detects failures caused by admission webhooks rejecting Pod creation.
    Triggered by:
      - event.reason == FailedCreate
      - event.message contains 'admission webhook'
    High enterprise relevance.
    """
    name = "AdmissionWebhookDenied"
    category = "Admission"
    priority = 29

    requires = {"pod": True}

    phases = ["Pending"]

    def matches(self, pod, events, context) -> bool:
        for e in events or []:
            reason = e.get("reason")
            msg = (e.get("message") or "").lower()
            if reason == "FailedCreate" and "admission webhook" in msg:
                return True
        return False

    def explain(self, pod, events, context):
        pod_name = pod.get("metadata", {}).get("name")
        namespace = pod.get("metadata", {}).get("namespace", "default")

        chain = CausalChain(
            causes=[
                Cause(
                    code="ADMISSION_WEBHOOK_DENIED",
                    message="Admission webhook rejected pod creation",
                    blocking=True,
                )
            ]
        )

        return {
            "rule": self.name,
            "root_cause": "Admission webhook denied pod creation",
            "confidence": 0.95,
            "blocking": True,
            "causes": chain,
            "evidence": [
                "FailedCreate event containing 'admission webhook'",
                f"Pod: {pod_name}",
                f"Namespace: {namespace}",
            ],
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Admission webhook prevented pod creation"
                ]
            },
            "likely_causes": [
                "Webhook policy rejecting pod spec",
                "Namespace-specific security restrictions",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get validatingwebhookconfigurations",
                "kubectl get mutatingwebhookconfigurations",
            ],
        }