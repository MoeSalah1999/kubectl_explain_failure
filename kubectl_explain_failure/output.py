import json
from typing import Any

# ----------------------------
# Output formatting
# ----------------------------


def output_result(result: dict[str, Any], fmt: str) -> None:
    """
    Nicely prints the Pod failure explanation.
    - Shows root_cause from the highest-confidence rule
    - Displays merged evidence, likely causes, suggested checks
    - Sorts items alphabetically for deterministic output
    """
    if fmt == "json":
        print(json.dumps(result, indent=2))
        return

    print(f"Pod: {result['pod']}")
    print(f"Phase: {result['phase']}")
    print(f"\nRoot cause:\n  {result['root_cause']}")
    print(f"\nConfidence: {int(result['confidence'] * 100)}%")

    # Alphabetically sort lists for cleaner deterministic output
    for key in ("evidence", "likely_causes", "suggested_checks"):
        items = sorted(result[key])
        if items:
            print(f"\n{key.replace('_', ' ').title()}:")
            for item in items:
                print(f"  - {item}")
