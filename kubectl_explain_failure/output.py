import json
import types
from typing import Any

yaml: types.ModuleType | None

try:
    import yaml as _yaml

    yaml = _yaml
except ImportError:
    yaml = None

# ----------------------------
# Output formatting
# ----------------------------


def output_result(result: dict[str, Any], fmt: str = "text") -> None:
    """
    Nicely prints the Pod failure explanation.
    - Shows root_cause from the highest-confidence rule
    - Displays merged evidence, likely causes, suggested checks
    - Includes resolution info and object evidence
    - Sorts items alphabetically for deterministic output
    """
    if fmt == "json":
        print(json.dumps(result, indent=2))
        return

    if fmt == "yaml":
        if yaml is None:
            print("[ERROR] PyYAML is not installed, cannot output YAML")
            return
        print(yaml.safe_dump(result, sort_keys=False))
        return

    # ----------------------------
    # Text output
    # ----------------------------
    print(f"Pod: {result['pod']}")
    print(f"Phase: {result['phase']}")
    print(f"\nRoot cause:\n  {result['root_cause']}")
    print(f"\nConfidence: {int(result['confidence'] * 100)}%")

    # Alphabetically sort lists for deterministic output
    for key in ("evidence", "likely_causes", "suggested_checks"):
        items = sorted(result.get(key, []))
        if items:
            print(f"\n{key.replace('_', ' ').title()}:")
            for item in items:
                print(f"  - {item}")

    # ----------------------------
    # Include resolution info if present
    # ----------------------------
    if "resolution" in result:
        res = result["resolution"]
        print("\nResolution:")
        print(f"  Winner: {res.get('winner')}")
        suppressed = res.get("suppressed", [])
        if suppressed:
            print(f"  Suppressed rules: {', '.join(suppressed)}")
        print(f"  Reason: {res.get('reason')}")

    # ----------------------------
    # Include object evidence if present
    # ----------------------------
    if "object_evidence" in result:
        print("\nObject Evidence:")
        for obj, items in result["object_evidence"].items():
            for item in sorted(items):
                print(f"  {obj}: {item}")
