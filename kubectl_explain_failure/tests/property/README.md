# Property Test Layout

This suite is organized by invariant type and system layer.

## Directory Map

- `generators/`
  - Generator correctness and algebra.
  - Put tests here when they validate `K8sSnapshot`, `snapshot_strategy()`, `inject()`, cloning, or generated shape guarantees.

- `engine/contracts/`
  - Engine output/input contract checks.
  - Put tests here for schema guarantees, confidence range/type validation, malformed input safety, and strict explain-contract enforcement.

- `engine/determinism/`
  - Determinism and order-invariance properties.
  - Put tests here for idempotence, event/object ordering invariance, permutation stability, and purity/no side-effects on caller inputs.

- `engine/resolution/`
  - Resolution and causal semantics.
  - Put tests here for winner/suppression invariants, blocking semantics, and causal-chain structural guarantees.

- `engine/filters/`
  - Category/rule filtering behavior.
  - Put tests here for `enabled_categories` / `disabled_categories` semantics, edge cases, and filter interactions.

- `rules/`
  - Rule-family specific properties.
  - Put tests here when they target behavior of specific rule families (PVC, scheduling, crashloop, compound interactions, context-shape handling).

## Placement Rule

When adding a new property test:

1. Identify the primary invariant (determinism, contract, resolution, filter, generator, or rule-specific).
2. Place the test in exactly one folder based on that primary invariant.
3. If a file mixes unrelated invariants, split it.

## Naming Convention

Use file names in the form:

- `test_prop_<layer>_<invariant>.py`

Examples:

- `test_prop_engine_confidence_bounds.py`
- `test_prop_filters_enabled_disabled_overlap.py`
- `test_prop_generators_snapshot_algebra.py`

## Note on Shared Utilities

- Shared Hypothesis strategies remain in `tests/property/strategies.py`.
- Shared property-test configuration remains in `tests/property/conftest.py`.
