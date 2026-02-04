#!/usr/bin/env python
# run_explain.py
import argparse
import json
import os
import sys

from engine import explain_failure

parser = argparse.ArgumentParser()
parser.add_argument("--pod", required=True)
parser.add_argument("--events", required=True)
parser.add_argument("--enable-categories", default="")
parser.add_argument("--disable-categories", default="")
parser.add_argument("--verbose", action="store_true")
parser.add_argument("--format", default="text", choices=["text", "json", "yaml"])
args = parser.parse_args()

with open(args.pod) as f:
    pod = json.load(f)
with open(args.events) as f:
    events = json.load(f)

result = explain_failure(
    pod,
    events.get("items", events),
    enabled_categories=(
        args.enable_categories.split() if args.enable_categories else None
    ),
    disabled_categories=(
        args.disable_categories.split() if args.disable_categories else None
    ),
    verbose=args.verbose,
)

if args.format == "json":
    print(json.dumps(result, indent=2))
elif args.format == "yaml":
    import yaml

    print(yaml.safe_dump(result, sort_keys=False))
else:
    print("Root cause:", result.get("root_cause"))
    print("Confidence:", result.get("confidence"))
    print("Evidence:", result.get("evidence"))
