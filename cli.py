import argparse
import os

from context import build_context
from model import load_json, normalize_events
from engine import explain_failure
from loader import load_rules
from output import output_result


def main():
    parser = argparse.ArgumentParser(description="Explain Kubernetes Pod failures")

    parser.add_argument("--pod", required=True, help="Path to Pod JSON")
    parser.add_argument("--events", required=True, help="Path to Events JSON")

    parser.add_argument(
        "--format",
        choices=["text", "json", "yaml"],
        default="text",
        help="Output format (text, json, yaml)"
    )

    parser.add_argument("--pvc")
    parser.add_argument("--node")
    parser.add_argument("--pvcs")
    parser.add_argument("--service")
    parser.add_argument("--endpoints")
    parser.add_argument("--statefulsets")
    parser.add_argument("--daemonsets")

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
    rules = load_rules(rule_folder=os.path.join(os.path.dirname(__file__), "rules"))

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

    output_result(result, args.format)
