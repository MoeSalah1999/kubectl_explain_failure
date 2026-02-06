import argparse
import os

from kubectl_explain_failure.context import build_context
from kubectl_explain_failure.engine import explain_failure
from kubectl_explain_failure.loader import load_plugins, load_rules
from kubectl_explain_failure.model import load_json, normalize_events
from kubectl_explain_failure.output import output_result


def main():
    parser = argparse.ArgumentParser(description="Explain Kubernetes Pod failures")

    parser.add_argument("--pod", required=True, help="Path to Pod JSON")
    parser.add_argument("--events", required=True, help="Path to Events JSON")

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
    rules += load_plugins(
        plugin_folder
    )  # if you want plugins, or use load_plugins(plugin_folder)

    print(f"[DEBUG] Loaded {len(rules)} rules")
    print("[DEBUG] Context keys:", list(context.keys()))
    for k, v in context.items():
        print(f"[DEBUG] {k} = {v}")
    for r in rules:
        print(f"  - {r.name} (category={r.category}, priority={r.priority})")

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

    if not rules:
        print("[WARNING] No rules loaded, check your rules/ and plugins/ folders")

    output_result(result, args.format)
