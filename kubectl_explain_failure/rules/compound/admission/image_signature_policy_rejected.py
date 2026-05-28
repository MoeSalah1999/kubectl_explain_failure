from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from kubectl_explain_failure.causality import CausalChain, Cause
from kubectl_explain_failure.rules.base_rule import FailureRule
from kubectl_explain_failure.timeline import Timeline, parse_time


class ImageSignaturePolicyRejectedRule(FailureRule):
    """
    Detect Pods rejected by admission-time image signature verification
    policies enforced by Kyverno, Gatekeeper, Sigstore/Cosign, Ratify,
    ImagePolicyWebhook, or vendor admission controllers.

    Real-world behavior:
    - production clusters increasingly require signed container images before
      workloads are admitted
    - admission controllers often reject unsigned images, expired signatures,
      untrusted transparency logs, missing attestations, or registry trust
      mismatches
    - the workload symptom is frequently confusing because the Pod may never
      schedule or only surfaces generic FailedCreate / FailedAdmission events
    - platform teams commonly enforce these policies selectively for production
      namespaces, protected registries, or critical workloads
    """

    name = "ImageSignaturePolicyRejected"
    category = "Compound"
    priority = 91
    deterministic = True

    phases = ["Pending"]

    requires = {
        "pod": True,
        "context": ["timeline"],
    }

    blocks = [
        "ImagePullBackOff",
        "ErrImagePull",
        "FailedCreate",
        "AdmissionWebhookDenied",
        "CreateContainerConfigError",
    ]

    WINDOW_MINUTES = 30
    CACHE_KEY = "_image_signature_policy_rejected_candidate"

    POLICY_MARKERS = (
        "cosign",
        "sigstore",
        "kyverno",
        "gatekeeper",
        "ratify",
        "notation",
        "imagepolicywebhook",
        "binary authorization",
        "image signature",
        "signature validation",
        "signature verification",
        "verifyimages",
        "verify-image",
        "policy webhook",
        "admission webhook",
        "attestation",
        "signed image",
        "unsigned image",
    )

    DENIAL_MARKERS = (
        "denied",
        "forbidden",
        "rejected",
        "failed validation",
        "validation failed",
        "signature verification failed",
        "no matching signatures",
        "missing signature",
        "image is not signed",
        "unsigned image",
        "failed cosign verification",
        "failed verifyimages",
        "attestation verification failed",
        "failed policy check",
        "does not satisfy policy",
        "violates policy",
        "failed admission",
        "admission webhook",
        "verification error",
        "certificate expired",
        "certificate signed by unknown authority",
        "rekor",
        "transparency log",
        "subject alternative name",
    )

    IMAGE_RE = re.compile(
        r"([a-zA-Z0-9\-\.]+(?::\d+)?(?:/[a-zA-Z0-9_\-\.]+)+(?::[\w.\-]+)?(?:@sha256:[a-f0-9]{64})?)"
    )

    def _parse_timestamp(self, raw: Any) -> datetime | None:
        if not isinstance(raw, str):
            return None
        try:
            return parse_time(raw)
        except Exception:
            return None

    def _event_time(self, event: dict[str, Any]) -> datetime | None:
        return (
            self._parse_timestamp(event.get("firstTimestamp"))
            or self._parse_timestamp(event.get("eventTime"))
            or self._parse_timestamp(event.get("lastTimestamp"))
            or self._parse_timestamp(event.get("timestamp"))
        )

    def _ordered_recent_events(self, timeline: Timeline) -> list[dict[str, Any]]:
        recent = timeline.events_within_window(self.WINDOW_MINUTES)
        indexed = list(enumerate(recent))

        return [
            event
            for _, event in sorted(
                indexed,
                key=lambda item: (
                    1 if self._event_time(item[1]) is None else 0,
                    self._event_time(item[1]) or datetime.min,
                    item[0],
                ),
            )
        ]

    def _message(self, event: dict[str, Any]) -> str:
        return str(event.get("message") or "")

    def _reason(self, event: dict[str, Any]) -> str:
        return str(event.get("reason") or "")

    def _source_component(self, event: dict[str, Any]) -> str:
        source = event.get("source")
        if isinstance(source, dict):
            return str(source.get("component") or "")
        return str(source or "")

    def _occurrences(self, event: dict[str, Any]) -> int:
        try:
            return max(1, int(event.get("count", 1)))
        except Exception:
            return 1

    def _pod_key(self, pod: dict[str, Any]) -> tuple[str, str]:
        metadata = pod.get("metadata", {}) or {}
        return (
            str(metadata.get("namespace") or "default"),
            str(metadata.get("name") or ""),
        )

    def _event_involves_pod(self, event: dict[str, Any], pod: dict[str, Any]) -> bool:
        involved = event.get("involvedObject")
        if not isinstance(involved, dict):
            return False

        namespace, pod_name = self._pod_key(pod)

        kind = str(involved.get("kind") or "").lower()
        if kind and kind != "pod":
            return False

        if pod_name and involved.get("name") and involved.get("name") != pod_name:
            return False

        if (
            namespace
            and involved.get("namespace")
            and involved.get("namespace") != namespace
        ):
            return False

        return True

    def _all_container_images(self, pod: dict[str, Any]) -> list[str]:
        images: list[str] = []

        spec = pod.get("spec", {}) or {}

        for field in ("containers", "initContainers", "ephemeralContainers"):
            for container in spec.get(field, []) or []:
                image = container.get("image")
                if isinstance(image, str) and image:
                    images.append(image)

        return sorted(dict.fromkeys(images))

    def _extract_images_from_text(self, text: str) -> list[str]:
        return list(dict.fromkeys(self.IMAGE_RE.findall(text or "")))

    def _is_signature_policy_event(
        self,
        event: dict[str, Any],
        pod: dict[str, Any],
        pod_images: list[str],
    ) -> bool:
        if not self._event_involves_pod(event, pod):
            return False

        text = " ".join(
            [
                self._reason(event),
                self._message(event),
                self._source_component(event),
            ]
        ).lower()

        if not any(marker in text for marker in self.POLICY_MARKERS):
            return False

        if not any(marker in text for marker in self.DENIAL_MARKERS):
            return False

        if any(image.lower() in text for image in pod_images):
            return True

        extracted = self._extract_images_from_text(text)
        if extracted:
            return any(image in pod_images for image in extracted)

        return True

    def _waiting_signature_failure(
        self,
        pod: dict[str, Any],
    ) -> tuple[bool, str, str]:
        for status in pod.get("status", {}).get("containerStatuses", []) or []:
            state = status.get("state", {}) or {}
            waiting = state.get("waiting", {}) or {}

            reason = str(waiting.get("reason") or "")
            message = str(waiting.get("message") or "")
            lowered = f"{reason} {message}".lower()

            if any(marker in lowered for marker in self.POLICY_MARKERS) and any(
                marker in lowered for marker in self.DENIAL_MARKERS
            ):
                return (
                    True,
                    str(status.get("name") or "<container>"),
                    message,
                )

        return False, "<container>", ""

    def _candidate(
        self,
        pod: dict[str, Any],
        events: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        timeline = context.get("timeline")
        if not isinstance(timeline, Timeline):
            return None

        namespace, pod_name = self._pod_key(pod)
        pod_images = self._all_container_images(pod)

        if not pod_images:
            return None

        ordered = self._ordered_recent_events(timeline)

        signature_events = [
            event
            for event in ordered
            if self._is_signature_policy_event(
                event,
                pod,
                pod_images,
            )
        ]

        waiting_failure, waiting_container, waiting_message = (
            self._waiting_signature_failure(pod)
        )

        if not signature_events and not waiting_failure:
            return None

        representative_event = (
            max(
                signature_events,
                key=lambda event: (
                    self._occurrences(event),
                    len(self._message(event)),
                ),
            )
            if signature_events
            else None
        )

        matched_images: set[str] = set()

        for event in signature_events:
            message = self._message(event)
            extracted = self._extract_images_from_text(message)

            for image in extracted:
                if image in pod_images:
                    matched_images.add(image)

            for image in pod_images:
                if image.lower() in message.lower():
                    matched_images.add(image)

        if not matched_images:
            matched_images.update(pod_images)

        duration_seconds = timeline.duration_between(
            lambda event: self._is_signature_policy_event(
                event,
                pod,
                pod_images,
            )
        )

        return {
            "namespace": namespace,
            "pod_name": pod_name,
            "images": sorted(matched_images),
            "event_count": sum(self._occurrences(event) for event in signature_events),
            "representative_message": (
                self._message(representative_event).strip()
                if representative_event
                else waiting_message
            ),
            "reason": (
                self._reason(representative_event)
                if representative_event
                else "SignaturePolicyRejected"
            ),
            "waiting_failure": waiting_failure,
            "waiting_container": waiting_container,
            "duration_seconds": max(0.0, duration_seconds),
        }

    def matches(self, pod, events, context) -> bool:
        candidate = self._candidate(pod, events, context)

        if candidate is None:
            context.pop(self.CACHE_KEY, None)
            return False

        context[self.CACHE_KEY] = candidate
        return True

    def explain(self, pod, events, context):
        candidate = context.get(self.CACHE_KEY) or self._candidate(
            pod,
            events,
            context,
        )

        if candidate is None:
            raise ValueError(
                "ImageSignaturePolicyRejected explain() called without match"
            )

        namespace = candidate["namespace"]
        pod_name = candidate["pod_name"]
        image_display = ", ".join(candidate["images"])

        evidence = [
            f"Pod {namespace}/{pod_name} uses image(s) protected by signature verification policy: {image_display}",
            f"Admission or policy enforcement rejected the image: {candidate['representative_message']}",
        ]

        if candidate["event_count"]:
            evidence.append(
                f"Observed {candidate['event_count']} signature policy rejection event occurrence(s) within {self.WINDOW_MINUTES} minutes"
            )

        if candidate["waiting_failure"]:
            evidence.append(
                f"Container '{candidate['waiting_container']}' remains blocked by image policy verification failure"
            )

        if candidate["duration_seconds"] > 0:
            evidence.append(
                f"Signature policy rejection events persisted for {candidate['duration_seconds'] / 60.0:.1f} minutes"
            )

        object_evidence = {
            f"pod:{pod_name}": [
                "Pod admission/startup is blocked by image signature or attestation policy enforcement"
            ]
        }

        for image in candidate["images"]:
            object_evidence[f"image:{image}"] = [
                "Container image failed signature verification or admission policy validation"
            ]

        chain = CausalChain(
            causes=[
                Cause(
                    code="CLUSTER_ENFORCES_IMAGE_SIGNATURE_POLICY",
                    message=(
                        "Cluster admission controls require trusted signed container images or verified attestations"
                    ),
                    role="configuration_context",
                ),
                Cause(
                    code="IMAGE_SIGNATURE_POLICY_VALIDATION_FAILED",
                    message=(
                        "Image signature, attestation, certificate, or transparency log verification failed"
                    ),
                    role="configuration_root",
                    blocking=True,
                ),
                Cause(
                    code="ADMISSION_CONTROLLER_REJECTED_WORKLOAD",
                    message=(
                        "Admission webhook or policy engine denied workload creation because the image is not policy compliant"
                    ),
                    role="admission_intermediate",
                ),
                Cause(
                    code="POD_STARTUP_BLOCKED_BY_IMAGE_POLICY",
                    message=(
                        "Pod cannot start because Kubernetes policy enforcement rejected the container image"
                    ),
                    role="workload_symptom",
                ),
            ]
        )

        return {
            "root_cause": (
                "Cluster image signature policy rejected the workload's container image"
            ),
            "confidence": 0.98,
            "blocking": True,
            "causes": chain,
            "evidence": evidence,
            "object_evidence": object_evidence,
            "likely_causes": [
                "Container image is unsigned but the cluster requires Cosign/Sigstore signatures",
                "Signature exists but does not match trusted identities, issuers, or certificate policy",
                "Required SBOM or attestation policy validation failed in Kyverno, Gatekeeper, or Ratify",
                "Transparency log, Rekor, Fulcio, or trust root verification failed",
                "The image was rebuilt, retagged, or mirrored after signing and the digest no longer matches the signature",
                "Admission policy only allows images from approved registries or trusted signing authorities",
            ],
            "suggested_checks": [
                f"kubectl describe pod {pod_name} -n {namespace}",
                "kubectl get validatingwebhookconfigurations",
                "kubectl get clusterpolicy,policy -A",
                "Inspect Kyverno, Gatekeeper, Ratify, or ImagePolicyWebhook controller logs",
                "Verify the image signature and attestations with cosign verify",
                "Confirm the image digest matches the signed artifact and trusted registry configuration",
            ],
        }
