from __future__ import annotations

from collections import Counter
from typing import Any

from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline


class MultipleIndependentFailuresRule(FailureRule):
    """
    Reports when the engine has found multiple actionable failures that are not
    in a parent/child suppression relationship.

    Real-world behavior:
    - a Pod can genuinely have more than one independent blocker, especially
      in multi-container workloads
    - a missing ConfigMap in one container does not explain an ImagePullBackOff
      in another container, and choosing either one as the single root cause is
      misleading
    - this rule runs after normal rule matching and suppression, so it only
      reports independent active diagnoses rather than secondary signals that
      were already explained by a stronger causal rule
    """

    name = "MultipleIndependentFailures"
    category = "Compound"
    priority = 8
    deterministic = False
    post_resolution = True

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    MIN_CONFIDENCE = 0.75
    WINDOW_MINUTES = 30
    CACHE_KEY = "_multiple_independent_failures_candidate"
    NON_ACTIONABLE_RULES = {
        "ContainerCreateConfigError",
        "FailedMount",
        "FailedScheduling",
        "LowConfidenceDiagnosis",
        "RootCauseAmbiguity",
        "SuppressedSignalExplanation",
    }
    INDEPENDENT_CATEGORIES = {
        "Admission",
        "ClusterInfrastructure",
        "ConfigMap",
        "Container",
        "Controller",
        "Image",
        "Networking",
        "Node",
        "PersistentVolumeClaim",
        "Scheduling",
        "Secret",
        "Storage",
    }

    COMPOUND_DOMAIN_MARKERS = (
        ("Config", "ConfigMap"),
        ("Secret", "Secret"),
        ("Image", "Image"),
        ("PVC", "PersistentVolumeClaim"),
        ("Volume", "Storage"),
        ("ControlPlane", "ClusterInfrastructure"),
        ("Node", "Node"),
        ("Network", "Networking"),
        ("Scheduling", "Scheduling"),
        ("Deployment", "Controller"),
        ("ReplicaSet", "Controller"),
        ("HPA", "Controller"),
    )

    CONTAINER_REASON_BY_DOMAIN = {
        "ConfigMap": {"CreateContainerConfigError"},
        "Image": {"ErrImagePull", "ImagePullBackOff"},
        "Secret": {"CreateContainerConfigError"},
    }

    def _recent_reasons(self, timeline: Timeline) -> list[str]:
        counts = Counter(
            str(event.get("reason", "")).strip()
            for event in timeline.events_within_window(self.WINDOW_MINUTES)
            if str(event.get("reason", "")).strip()
        )
        return [reason for reason, _ in counts.most_common(5)]

    def _domain_for(self, item: dict[str, Any]) -> str:
        category = str(item.get("category", "")).strip()
        if category != "Compound":
            return category

        text = " ".join(
            [
                str(item.get("name", "")),
                str(item.get("root_cause", "")),
            ]
        )
        for marker, domain in self.COMPOUND_DOMAIN_MARKERS:
            if marker.lower() in text.lower():
                return domain
        return category

    def _actionable_matches(self, context: dict[str, Any]) -> list[dict[str, Any]]:
        engine_state = context.get("_engine_state", {}) or {}
        active = engine_state.get("active_matched_rules", []) or []
        suppressed = engine_state.get("suppressed_matched_rules", []) or []
        matches = [*active, *suppressed]
        result: list[dict[str, Any]] = []

        for item in matches:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip()
            domain = self._domain_for(item)
            confidence = float(item.get("confidence", 0.0) or 0.0)

            if not name or name in self.NON_ACTIONABLE_RULES:
                continue
            if domain not in self.INDEPENDENT_CATEGORIES:
                continue
            if confidence < self.MIN_CONFIDENCE:
                continue

            result.append(
                {
                    **item,
                    "independent_domain": domain,
                    "multiple_failures_source": (
                        "active" if item in active else "suppressed"
                    ),
                }
            )

        by_domain: dict[str, dict[str, Any]] = {}
        for item in result:
            domain = str(item["independent_domain"])
            current = by_domain.get(domain)
            if current is None:
                by_domain[domain] = item
                continue

            item_is_active = item.get("multiple_failures_source") == "active"
            current_is_active = current.get("multiple_failures_source") == "active"
            if item_is_active and not current_is_active:
                by_domain[domain] = item
                continue
            if item_is_active == current_is_active and float(
                item.get("confidence", 0.0) or 0.0
            ) > float(current.get("confidence", 0.0) or 0.0):
                by_domain[domain] = item

        return sorted(
            by_domain.values(),
            key=lambda item: (
                str(item.get("independent_domain", "")),
                str(item.get("name", "")),
            ),
        )

    def _containers_for_match(
        self,
        pod: dict[str, Any],
        item: dict[str, Any],
    ) -> set[str]:
        domain = str(item.get("independent_domain", ""))
        expected_reasons = self.CONTAINER_REASON_BY_DOMAIN.get(domain)
        if not expected_reasons:
            return set()

        containers: set[str] = set()
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            name = str(status.get("name", "")).strip()
            waiting = (status.get("state", {}) or {}).get("waiting", {}) or {}
            reason = str(waiting.get("reason", "")).strip()
            if name and reason in expected_reasons:
                containers.add(name)
        return containers

    def _with_container_scope(
        self,
        pod: dict[str, Any],
        active: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        scoped: list[dict[str, Any]] = []
        for item in active:
            containers = self._containers_for_match(pod, item)
            if not containers:
                return []
            scoped.append({**item, "containers": sorted(containers)})
        return scoped

    def _candidate(self, pod: dict[str, Any], context: dict[str, Any]):
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        active = self._actionable_matches(context)
        if len(active) < 2:
            return None

        scoped = self._with_container_scope(pod, active)
        if len(scoped) < 2:
            return None

        seen_containers: set[str] = set()
        for item in scoped:
            containers = set(item.get("containers", []) or [])
            if seen_containers.intersection(containers):
                return None
            seen_containers.update(containers)

        categories = {
            str(item.get("independent_domain", "")).strip()
            for item in scoped
            if str(item.get("independent_domain", "")).strip()
        }
        root_causes = {
            str(item.get("root_cause", "")).strip()
            for item in scoped
            if str(item.get("root_cause", "")).strip()
        }
        if len(categories) < 2 or len(root_causes) < 2:
            return None

        engine_state = context.get("_engine_state", {}) or {}
        preliminary = engine_state.get("preliminary_result") or {}

        return {
            "active": scoped,
            "categories": sorted(categories),
            "recent_reasons": self._recent_reasons(timeline),
            "preliminary": preliminary,
        }

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
                "MultipleIndependentFailures explain() called without match"
            )

        pod_name = pod.get("metadata", {}).get("name", "<pod>")
        active = candidate["active"]
        categories = candidate["categories"]
        recent_reasons = candidate["recent_reasons"]
        preliminary = candidate["preliminary"]

        names = [str(item.get("name", "")) for item in active]
        root_causes = [str(item.get("root_cause", "")) for item in active]
        confidence = min(
            0.97,
            max(float(item.get("confidence", 0.0) or 0.0) for item in active) + 0.01,
        )

        evidence = [
            f"Engine found {len(active)} independent active diagnoses: {', '.join(names)}",
            f"Independent failure domains involved: {', '.join(categories)}",
        ]
        if recent_reasons:
            evidence.append(
                "Recent event timeline contains distinct failure reasons: "
                f"{', '.join(recent_reasons)}"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                "Multiple unsuppressed actionable diagnoses remain active after engine resolution"
            ],
            "engine:multiple-independent-failures": [
                f"{item.get('name')}: {item.get('root_cause')}" for item in active
            ],
        }

        return {
            "root_cause": "Multiple independent failures require separate remediation",
            "confidence": confidence,
            "blocking": any(bool(item.get("blocking", False)) for item in active),
            "causes": [
                {
                    "code": "MULTIPLE_ACTIVE_DIAGNOSES",
                    "message": "Engine resolution left multiple actionable diagnoses active",
                    "role": "diagnostic_context",
                },
                {
                    "code": "INDEPENDENT_FAILURE_DOMAINS",
                    "message": f"Active diagnoses span independent domains: {', '.join(categories)}",
                    "role": "configuration_root",
                    "blocking": True,
                },
                {
                    "code": "SEPARATE_REMEDIATION_REQUIRED",
                    "message": "Each independent failure must be investigated and remediated separately",
                    "role": "diagnostic_symptom",
                },
            ],
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": root_causes,
            "suggested_checks": [
                f"kubectl describe pod {pod_name}",
                "Address each listed independent diagnosis instead of treating later symptoms as caused by the first one",
                "Re-run the diagnostic after fixing one failure to confirm the remaining active diagnosis",
            ],
            "resolution": {
                "winner": self.name,
                "suppressed": list(
                    preliminary.get("resolution", {}).get("suppressed", [])
                ),
                "reason": "Multiple unsuppressed actionable diagnoses remain after normal engine resolution",
                "independent_failures": [
                    {
                        "name": str(item.get("name", "")),
                        "category": str(item.get("independent_domain", "")),
                        "root_cause": str(item.get("root_cause", "")),
                        "confidence": float(item.get("confidence", 0.0) or 0.0),
                    }
                    for item in active
                ],
            },
        }
