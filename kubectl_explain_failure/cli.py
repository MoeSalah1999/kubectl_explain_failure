import argparse
import logging
import os
import shutil
import subprocess

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.live_adapter import LiveIntrospectionError, fetch_live_snapshot
from kubectl_explain_failure.loader import load_plugins, load_rules
from kubectl_explain_failure.model import load_json, normalize_events
from kubectl_explain_failure.output import output_result

MAX_TIMEOUT_SECONDS = 300
MAX_EVENT_LIMIT = 5000
MAX_EVENT_CHUNK_SIZE = 1000
MAX_RETRIES = 5
MAX_RETRY_BACKOFF_SECONDS = 10.0


def _apply_live_completeness_penalty(result: dict, live_metadata: dict) -> None:
    confidence = float(result.get("confidence", 0.0))
    rbac_missing = len(live_metadata.get("missing_due_to_rbac", []))

    if rbac_missing <= 0:
        return

    penalty = min(0.35, 0.05 * rbac_missing)
    adjusted = max(0.0, min(1.0, confidence * (1.0 - penalty)))

    result["confidence"] = adjusted
    result.setdefault("confidence_adjustments", []).append(
        {
            "reason": "rbac_missing_context",
            "penalty_factor": round(penalty, 4),
            "rbac_missing_total": rbac_missing,
        }
    )


def _build_provenance_metadata(
    *,
    source: str,
    context: dict,
    events: list[dict],
    warnings: list[str],
    live_metadata: dict | None,
) -> dict:
    obj_counts = {
        kind: len(mapping)
        for kind, mapping in context.get("objects", {}).items()
        if isinstance(mapping, dict)
    }

    provenance = {
        "source": source,
        "event_count": len(events),
        "fetched_object_counts": obj_counts,
        "fetched_object_total": sum(obj_counts.values()),
        "fetch_warning_count": len(warnings),
        "fetch_warnings": warnings,
        "missing_kinds": [],
        "missing_kinds_by_reason": {},
    }

    if live_metadata:
        provenance["missing_kinds"] = list(live_metadata.get("missing_kinds", []))
        provenance["missing_kinds_by_reason"] = dict(
            live_metadata.get("missing_kinds_by_reason", {})
        )
        if live_metadata.get("trace_id"):
            provenance["trace_id"] = live_metadata["trace_id"]

    return provenance


def _validate_live_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if shutil.which("kubectl") is None:
        parser.error("Live mode requires kubectl in PATH")

    if args.kubeconfig and not os.path.isfile(args.kubeconfig):
        parser.error(f"kubeconfig file not found: {args.kubeconfig}")

    if args.timeout <= 0 or args.timeout > MAX_TIMEOUT_SECONDS:
        parser.error(
            f"--timeout must be between 1 and {MAX_TIMEOUT_SECONDS} seconds"
        )

    if args.event_limit < 1 or args.event_limit > MAX_EVENT_LIMIT:
        parser.error(
            f"--event-limit must be between 1 and {MAX_EVENT_LIMIT}"
        )

    if args.event_chunk_size < 1 or args.event_chunk_size > MAX_EVENT_CHUNK_SIZE:
        parser.error(
            f"--event-chunk-size must be between 1 and {MAX_EVENT_CHUNK_SIZE}"
        )

    if args.retries < 0 or args.retries > MAX_RETRIES:
        parser.error(f"--retries must be between 0 and {MAX_RETRIES}")

    if (
        args.retry_backoff <= 0.0
        or args.retry_backoff > MAX_RETRY_BACKOFF_SECONDS
    ):
        parser.error(
            f"--retry-backoff must be between 0 and {MAX_RETRY_BACKOFF_SECONDS} seconds"
        )


def _emit_live_fatal_error(
    *,
    message: str,
    output_format: str,
    namespace: str,
    pod_name: str,
    trace_id: str | None,
) -> None:
    if output_format in {"json", "yaml"}:
        error_payload = {
            "source": "live",
            "error": message,
            "root_cause": "Live introspection failed",
            "confidence": 0.0,
            "blocking": False,
            "evidence": [],
            "likely_causes": [],
            "suggested_checks": [
                f"kubectl get pod {pod_name} -n {namespace}",
                f"kubectl get events -n {namespace}",
            ],
        }
        if trace_id:
            error_payload["trace_id"] = trace_id

        output_result(error_payload, output_format)
    else:
        suffix = f" [trace_id={trace_id}]" if trace_id else ""
        print(f"[ERROR] {message}{suffix}")


def main():
    parser = argparse.ArgumentParser(description="Explain Kubernetes Pod failures")

    parser.add_argument("resource", nargs="?", help="Live mode resource (pod|pods)")
    parser.add_argument("name", nargs="?", help="Live mode pod name")

    parser.add_argument("--pod", help="Path to Pod JSON (snapshot mode)")
    parser.add_argument("--events", help="Path to Events JSON (snapshot mode)")

    parser.add_argument("--live", action="store_true", help="Fetch data from a live cluster")
    parser.add_argument("--pod-name", help="Pod name for live mode")
    parser.add_argument("--namespace", default="default", help="Kubernetes namespace for live mode")
    parser.add_argument(
        "--context",
        dest="kube_context",
        help="Kube context name for live mode",
    )
    parser.add_argument("--kubeconfig", help="Path to kubeconfig for live mode")
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Kubectl request timeout in seconds (live mode)",
    )
    parser.add_argument(
        "--event-limit",
        type=int,
        default=200,
        help="Maximum number of pod events to keep in live mode",
    )
    parser.add_argument(
        "--event-chunk-size",
        type=int,
        default=200,
        help="Kubectl server-side chunk size for live event listing",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="Retry count for transient kubectl failures in live mode",
    )
    parser.add_argument(
        "--retry-backoff",
        type=float,
        default=0.25,
        help="Initial retry backoff in seconds for live mode",
    )
    parser.add_argument(
        "--trace-id",
        default=None,
        help="Optional trace identifier to correlate live fetch logs",
    )

    parser.add_argument(
        "--format",
        choices=["text", "json", "yaml"],
        default="text",
        help="Output format (text, json, yaml)",
    )

    parser.add_argument("--pv")
    parser.add_argument("--pvc")
    parser.add_argument("--node")
    parser.add_argument("--pvcs")
    parser.add_argument("--secret")
    parser.add_argument("--service")
    parser.add_argument("--endpoints")
    parser.add_argument("--replicaset")
    parser.add_argument("--deployment")
    parser.add_argument("--daemonsets")
    parser.add_argument("--storageclass")
    parser.add_argument("--statefulsets")
    parser.add_argument("--serviceaccount")

    parser.add_argument("--enable-categories", nargs="*", default=None)
    parser.add_argument("--disable-categories", nargs="*", default=None)
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(message)s")

    live_warnings: list[str] = []
    live_metadata: dict | None = None

    if args.live:
        if args.resource and args.resource not in {"pod", "pods"}:
            parser.error("Live mode positional resource must be 'pod' or 'pods'")

        pod_name = args.name or args.pod_name
        if not pod_name:
            parser.error(
                "Live mode requires pod name: use 'pod <name> --live' or '--pod-name <name> --live'"
            )

        _validate_live_args(parser, args)

        try:
            pod, events, context, live_warnings, live_metadata = fetch_live_snapshot(
                pod_name=pod_name,
                namespace=args.namespace,
                kube_context=args.kube_context,
                kubeconfig=args.kubeconfig,
                timeout_seconds=args.timeout,
                event_limit=args.event_limit,
                event_chunk_size=args.event_chunk_size,
                retry_count=args.retries,
                retry_backoff_seconds=args.retry_backoff,
                trace_id=args.trace_id,
            )
        except (LiveIntrospectionError, subprocess.TimeoutExpired, OSError) as exc:
            _emit_live_fatal_error(
                message=str(exc),
                output_format=args.format,
                namespace=args.namespace,
                pod_name=pod_name,
                trace_id=args.trace_id,
            )
            raise SystemExit(2) from exc

        source = "live"
    else:
        if not args.pod or not args.events:
            parser.error("Snapshot mode requires --pod and --events")

        context = build_context(args)

        pod = load_json(args.pod)
        events_raw = load_json(args.events)
        events = normalize_events(events_raw)
        source = "snapshot"

    rules_folder = os.path.join(os.path.dirname(__file__), "rules")
    rules = load_rules(rule_folder=rules_folder)

    plugin_folder = os.path.join(os.path.dirname(__file__), "plugins")
    rules += load_plugins(plugin_folder)

    if args.verbose:
        print(f"[DEBUG] Loaded {len(rules)} rules")
        print("[DEBUG] Context keys:", list(context.keys()))
        for r in rules:
            print(f"  - {r.name} (category={r.category}, priority={r.priority})")
        if live_warnings:
            for warning in live_warnings:
                print(f"[WARN] {warning}")

    result = explain_failure(
        pod,
        events,
        context,
        rules=rules,
        enabled_categories=args.enable_categories,
        disabled_categories=args.disable_categories,
        verbose=args.verbose,
    )

    result["source"] = source
    if live_warnings:
        result["live_warnings"] = live_warnings

    if live_metadata:
        _apply_live_completeness_penalty(result, live_metadata)
        result["live_metadata"] = live_metadata

    result["provenance"] = _build_provenance_metadata(
        source=source,
        context=context,
        events=events,
        warnings=live_warnings,
        live_metadata=live_metadata,
    )

    if not rules:
        print("[WARNING] No rules loaded, check your rules/ and plugins/ folders")

    output_result(result, args.format)
