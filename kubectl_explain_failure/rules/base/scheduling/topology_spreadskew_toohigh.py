import re

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import build_timeline


SKEW_REGEX = re.compile(
    r"skew.*?(\d+).*?maxskew.*?(\d+)", re.IGNORECASE
)

TOPOLOGY_KEY_REGEX = re.compile(
    r"topology.*?key.*?([a-zA-Z0-9\.\-\/]+)", re.IGNORECASE
)


class PodTopologySpreadSkewTooHighRule(FailureRule):
    """
    Detects scheduling failures where topology spread skew exceeds maxSkew.

    Signals:
    - Pod defines topologySpreadConstraints
    - Scheduler emits FailedScheduling events
    - Event message references topology spread skew exceeding maxSkew

    Interpretation:
    The scheduler attempted to place the Pod while honoring topology
    spread constraints. However, the existing Pod distribution across
    topology domains caused the skew to exceed the configured maxSkew.

    Unlike TopologySpreadUnsatisfiable, this represents skew drift
    caused by current cluster distribution rather than an impossible
    scheduling constraint.

    Scope:
    - Scheduler-level failure
    - Deterministic when constraints are present
    """

    name = "PodTopologySpreadSkewTooHigh"
    category = "Scheduling"
    priority = 20
    deterministic = True
    blocks = []
    requires = {
        "pod": True,
    }

    def _extract_skew(self, message: str):
        """
        Attempt to extract skew/maxSkew from scheduler message.
        """
        match = SKEW_REGEX.search(message)
        if not match:
            return None, None

        try:
            skew = int(match.group(1))
            max_skew = int(match.group(2))
            return skew, max_skew
        except Exception:
            return None, None

    def _extract_topology_key(self, message: str):
        match = TOPOLOGY_KEY_REGEX.search(message)
        if match:
            return match.group(1)
        return None

    def matches(self, pod, events, context) -> bool:
        spec = pod.get("spec", {})
        constraints = spec.get("topologySpreadConstraints")

        if not constraints:
            return False

        timeline = build_timeline(events)

        failed = [e for e in timeline.events if e.get("reason") == "FailedScheduling"]

        for e in failed:
            msg = (e.get("message") or "").lower()

            if "topologyspread" not in msg and "topology spread" not in msg:
                continue

            if "skew" not in msg:
                continue

            if "unsatisfiable" in msg:
                # handled by topology_spread_unsatisfiable rule
                continue

            skew, max_skew = self._extract_skew(msg)

            if skew is not None and max_skew is not None:
                if skew > max_skew:
                    return True

            # fallback when numbers are not parsed but skew mentioned
            if "skew" in msg and "maxskew" in msg:
                return True

        return False

    def explain(self, pod, events, context):
        spec = pod.get("spec", {})
        constraints = spec.get("topologySpreadConstraints", [])

        timeline = build_timeline(events)

        failed = [e for e in timeline.events if e.get("reason") == "FailedScheduling"]

        skew_value = None
        max_skew_value = None
        topology_key = None

        evidence_msgs = []

        for e in failed:
            msg = e.get("message")
            if not msg:
                continue

            lower = msg.lower()

            if "skew" not in lower:
                continue

            evidence_msgs.append(msg)

            skew, max_skew = self._extract_skew(msg)

            if skew is not None:
                skew_value = skew
            if max_skew is not None:
                max_skew_value = max_skew

            key = self._extract_topology_key(msg)
            if key:
                topology_key = key

        chain = CausalChain(
            causes=[
                Cause(
                    code="TOPOLOGY_SPREAD_CONSTRAINT_DEFINED",
                    message="Pod defines topology spread constraints",
                    role="scheduling_context",
                ),
                Cause(
                    code="TOPOLOGY_SKEW_EXCEEDED",
                    message="Existing pod distribution exceeded allowed topology spread skew",
                    role="scheduling_root",
                    blocking=True,
                ),
                Cause(
                    code="POD_UNSCHEDULABLE_TOPOLOGY_SKEW",
                    message="Scheduler rejected the Pod because topology skew exceeded maxSkew",
                    role="workload_symptom",
                ),
            ]
        )

        constraint_info = []
        for c in constraints:
            key = c.get("topologyKey")
            max_skew = c.get("maxSkew")

            if key and max_skew is not None:
                constraint_info.append(f"{key} (maxSkew={max_skew})")

        evidence = [
            "Pod.spec.topologySpreadConstraints present",
            f"{len(failed)} FailedScheduling events observed",
        ]

        if topology_key:
            evidence.append(f"Topology key: {topology_key}")

        if skew_value is not None and max_skew_value is not None:
            evidence.append(
                f"Observed skew {skew_value} > allowed maxSkew {max_skew_value}"
            )

        evidence.extend(evidence_msgs[:2])

        pod_name = pod.get("metadata", {}).get("name", "unknown")

        return {
            "rule": self.name,
            "root_cause": "Topology spread skew exceeded maxSkew preventing scheduling",
            "confidence": 0.96 if skew_value is not None else 0.92,
            "causes": chain,
            "blocking": True,
            "evidence": evidence,
            "object_evidence": {
                f"pod:{pod_name}": [
                    "Topology spread constraints defined",
                    "Scheduler rejected Pod due to skew > maxSkew",
                ]
            },
            "likely_causes": [
                "Too many Pods scheduled in a single topology domain",
                "Insufficient nodes available in other topology zones",
                "Rolling deployment temporarily skewed pod distribution",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "kubectl get pods -o wide",
                "kubectl get nodes --show-labels",
                "Review topologySpreadConstraints configuration",
            ],
        }