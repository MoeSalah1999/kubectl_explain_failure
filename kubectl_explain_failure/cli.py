import argparse
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.live_adapter import fetch_live_snapshot
from kubectl_explain_failure.loader import load_plugins, load_rules
from kubectl_explain_failure.model import load_json, normalize_events
from kubectl_explain_failure.output import output_result


def main():
    parser = argparse.ArgumentParser(description="Explain Kubernetes Pod failures")

    # Live-style positional usage:
    # kubectl explain-failure pod <name> --live
    parser.add_argument("resource", nargs="?", help="Live mode resource (pod|pods)")
    parser.add_argument("name", nargs="?", help="Live mode pod name")

    # Snapshot mode inputs
    parser.add_argument("--pod", help="Path to Pod JSON (snapshot mode)")
    parser.add_argument("--events", help="Path to Events JSON (snapshot mode)")

    # Live mode controls
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

    live_warnings: list[str] = []

    if args.live:
        if args.resource and args.resource not in {"pod", "pods"}:
            parser.error("Live mode positional resource must be 'pod' or 'pods'")

        pod_name = args.name or args.pod_name
        if not pod_name:
            parser.error(
                "Live mode requires pod name: use 'pod <name> --live' or '--pod-name <name> --live'"
            )

        pod, events, context, live_warnings = fetch_live_snapshot(
            pod_name=pod_name,
            namespace=args.namespace,
            kube_context=args.kube_context,
            kubeconfig=args.kubeconfig,
            timeout_seconds=args.timeout,
        )
    else:
        if not args.pod or not args.events:
            parser.error("Snapshot mode requires --pod and --events")

        # Build cross-object context
        context = build_context(args)

        # Load core objects
        pod = load_json(args.pod)
        events_raw = load_json(args.events)
        events = normalize_events(events_raw)

    # Load rules
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

    # Run engine
    result = explain_failure(
        pod,
        events,
        context,
        rules=rules,
        enabled_categories=args.enable_categories,
        disabled_categories=args.disable_categories,
        verbose=args.verbose,
    )

    result["source"] = "live" if args.live else "snapshot"
    if live_warnings:
        result["live_warnings"] = live_warnings

    if not rules:
        print("[WARNING] No rules loaded, check your rules/ and plugins/ folders")

    output_result(result, args.format)
