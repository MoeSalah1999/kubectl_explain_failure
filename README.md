"""
# kubectl-explain-failure

kubectl-explain-failure is a deterministic diagnostic engine that explains **why a Kubernetes Pod is failing** by constructing structured causal explanations from Kubernetes object state and event timelines.

Kubernetes exposes signals (Pod status, Events, PVC state, Node conditions), but it does not synthesize them into root causes.  
This project builds an explicit reasoning layer on top of those signals.

It is a **read-only explanation engine**, not a controller, not a fixer, and not an ML system.

---

# Core Idea

Kubernetes gives you:

- Pod.status
- Container states
- Events
- PVC / PV / StorageClass
- Node conditions
- Owner references (ReplicaSet / Deployment / StatefulSet)

You still have to manually answer:

> “What is the most likely reason this Pod is failing?”

This tool answers that question using:

- Explicit rule contracts
- Structured object-graph reasoning
- Timeline normalization
- Causal chains
- Conflict resolution
- Compositional confidence scoring

All behavior is deterministic and fully test-covered.

---

# What This Tool Does

## 1. Object Graph Reasoning (Not Flat Inputs)

The engine operates on a normalized object graph:

> context = {
      "pod": pod,
      "events": events,
      "objects": {
          "pvc": {...},
          "pv": {...},
          "node": {...},
          "storageclass": {...},
          "owner": {...},
      }
  }


Supported first-class objects include:

- Pod
- PersistentVolumeClaim
- PersistentVolume
- StorageClass
- Node
- ReplicaSet
- Deployment
- StatefulSet
- ServiceAccount
- Secrets
- NodeConditions (structured)


### Rules can declare:

> “requires = {
    "objects": ["pvc", "pv"],
    "optional": ["storageclass"]
}”

The engine normalizes legacy flat context into this object-graph model automatically.
Object state always has precedence over raw Events.

### Precedence model:

> Object state > Conditions > Timeline > Raw events

This significantly improves determinism and confidence accuracy.


## 2. Timeline Normalization & Temporal Reasoning

Raw Kubernetes events are normalized into structured semantic signals:

- NormalizedEvent:
    - kind   (Scheduling / Image / Volume / Generic)
    - phase  (Failure / Info)
    - reason
    - source


### Timeline features include:

- Semantic matching (timeline.has(kind="Scheduling", phase="Failure"))
- Repeated reason detection
- Pattern matching
- Duration measurement between related events
- Repeated-event escalation detection
- Temporal compound rules are supported:
- Rapid restart escalation
- Repeated probe failure escalation
- Scheduling flapping
- PVC pending too long
- Image updated → crash loop
- CrashLoop after config change

This moves diagnosis from snapshot inspection to incident reasoning.

## 3. Explicit Causal Chains

Rules do not return flat explanations they return structured causal chains:

> CausalChain(
    causes=[...],
    symptoms=[...],
    contributing=[...],
)


The engine then:

1. Aggregates matches
2. Selects the highest-confidence root cause
3. Preserves supporting causes
4. Applies suppression semantics
5. Emits a structured result

This enables explainability and deterministic reasoning.

## 4. Conflict Resolution & Suppression

Rules can explicitly block other rules:

> blocks = ["FailedScheduling", "UnschedulableTaint"]

Compound rules automatically subsume lower-level crash signals.


### Resolution logic:

1. Rules are evaluated in priority order
2. Compound rules suppress container-level signals
3. Suppression map is preserved in output
4. Only unsuppressed winners are returned

### Regression tests verify:

- PVC dominance over scheduling errors
- Compound rule precedence
- YAML rule safety
- Engine invariants

## 5. Compositional Confidence Model

Confidence is not static.

Final confidence is computed as:

> confidence =
      rule_confidence
      × evidence_quality
      × data_completeness
      × conflict_penalty


This makes confidence:

- Deterministic
- Explainable
- Predictable under partial input
- Stable under rule reordering

Confidence is always bounded to [0,1].


# Supported failure patterns: (all rules support suppression/resolution semantics):

## Admission & Policy

- AdmissionWebhookDenied
- PrivilegedNotAllowed
- SecurityContextViolation
- LimitRangeViolation
- ResourceQuotaExceeded
- RBACForbidden
- ServiceAccountMissingRule
- ServiceAccountRBAC

## Scheduling & Placement

- FailedScheduling
- AffinityUnsatisfiable
- TopologySpreadUnsatisfiable
- NodeSelectorMismatch
- InsufficientResources
- UnschedulableTaint
- HostPortConflict
- PreemptedByHigherPriority
- Compound:
    - SchedulingFlapping
    - PendingUnschedulableRule
    - PriorityPreemptionChain

## Node & Eviction

- NodeMemoryPressure
- NodePIDPressure
- NodeDiskPressure
- EvictedRule
- Compound:
    - NodeNotReadyEvictedRule
    - PVCBoundThenNodePressureRule
    - PVCBoundNodeDiskPressureMountRule

## Storage & Volume

- PVCNotBound
- PVReleasedOrFailed
- PVCMountFailed
- FailedMount
- PVCZoneMismatch
- StorageClassProvisionerMissing
- ConfigMapNotFound
- Compound:
    - PVCMountFailureRule
    - PVCPendingTooLongRule
    - DynamicProvisioningTimeout
    - PVCPendingThenCrashloopRule
    - PVCThenCrashloopRule
    - PVCThenImagePullFailRule
    - PVCRecoveredButAppStillFailing

## Image & Container Lifecycle

- ImagePullError
- ImagePullBackOff
- ImagePullSecretMissing
- InvalidEntrypoint
- ContainerCreateConfigError
- CrashLoopBackoff
- OOMKilled containers
- Compound:
    - CrashLoopOOMKilledRule
    - CrashLoopLivenessProbeRule
    - CrashLoopAfterConfigChange
    - CrashloopWithConfigOrSecret
    - ImagePullSecretMissingCompound
    - ImageUpdatedThenCrashLoop
    - RapidRestartEscalationRule

## Probes

- ReadinessProbeFailure
- StartupProbeFailure
- Compound:
    - RepeatedProbeFailureEscalation

## Networking

- DNSResolutionFailure
- CNIPluginFailure
- Compound:
    - NetworkPolicyBlocked

## Controllers / Owners

- ReplicaSetCreateFailure
- ReplicaSetUnavailable
- DeploymentProgressDeadlineExceeded
- StatefulSetUpdateBlocked
- Compound:
    - OwnerBlockedPod

## Multi-Container / Init

- InitContainerFailureRule
- Compound:
    - InitContainerBlocksMain
    - MultiContainerPartialFailure

## Engine-Level / Resolution

- Compound:
    - ConflictingSignalsResolution



- Rules are evaluated in priority order.
- High-priority rules can suppress lower-priority rules, preventing misleading explanations.
- First matching, unsuppressed rule produces the explanation.
- Golden tests assert that suppression works correctly.


# Installation (Development Mode)

To install the package locally in development mode, allowing editable imports:

- git clone https://github.com/MoeSalah1999/kubectl_explain_failure
- cd kubectl_explain_failure
- python -m pip install -e .

This ensures you can import the package as:

> from kubectl_explain_failure.engine import explain_failure

and run tests or scripts directly.

# Usage
## Basic usage:
python -m kubectl_explain_failure \
  --pod /kubectl_explain_failure/tests/fixtures/pod.json \
  --events /kubectl_explain_failure/tests/fixtures/events.json


## With optional PVC or Node context:
python -m kubectl_explain_failure \
  --pod /kubectl_explain_failure/tests/fixtures/pending_pod.json \
  --events /kubectl_explain_failure/tests/fixtures/empty_events.json \
  --pvc /kubectl_explain_failure/tests/fixtures/pvc_pending.json \
  --node /kubectl_explain_failure/tests/fixtures/node_disk_pressure.json

# Output Structure

**The output includes:**

- root_cause
- confidence
- causal_chain
- suppressed_rules
- evidence
- suggested_next_checks
- metadata

Output is fully deterministic for identical inputs.

# Testing

### The project uses:

- pytest
- tox
- mypy
- Golden snapshot testing
- Regression invariants

Tests are **not included in the installed package** and must be run from the source tree.
To run tests in the development environment:

- tox
- tox -e format   # code formatting
- tox -e lint     # static linting
- tox -e typing   # mypy type checks
- tox -e test     # pytest suite, including golden tests

Tox automatically installs required dependencies, including:

- pytest
- mypy
- PyYAML

This ensures tests run in a clean environment and type checks are enforced.

### Golden tests validate:

- Exact explanation structure
- Confidence stability
- Suppression correctness
- Temporal reasoning behavior

### Regression tests validate:

- Engine invariants
- YAML rule safety
- Object-graph compatibility
- Rule contract enforcement
- PVC dominance semantics

# Architecture Overview

### Core modules:

- engine.py – rule evaluation, resolution, confidence composition
- causality.py – CausalChain and Resolution structures
- context.py – context normalization
- timeline.py – normalized timeline abstraction
- relations.py – object dependency graph logic
- loader.py – rule and plugin discovery
- rules/ – rule corpus (Python + YAML)
- tests/ – golden + regression + contract tests

### Rule contract (base_rule.py):

> "class FailureRule:
>     name: str
>     category: str
>     priority: int
>     requires: dict
> 
>     def matches(...)
>     def explain(...)"


All rules must be deterministic and side-effect free.

# What this tool does NOT do
- No live cluster access
- No Kubernetes API client
- No controllers, CRDs, or admission hooks
- No automatic remediation
- No machine learning or prediction

This is a **diagnostic explainer**, not a fixer.

# Design notes
- Rule-based, not implicit
Each diagnostic is an explicit rule that can be reviewed, tested, and extended.

- Read-only by design
All inputs are files; no cluster mutation or API access is required.

- Deterministic output
The same inputs always produce the same explanation.

- Reviewable architecture
Heuristics are isolated from parsing and output logic.

# Why this exists (despite kubectl describe)

kubectl describe exposes raw data.
This tool answers a different question:

“Given these signals, what is the most likely reason this Pod is failing?”

It complements existing tooling rather than replacing it.


# Future work

- Additional failure heuristics
- Structured output for automation
- Optional kubectl plugin wrapper

Live cluster access is intentionally out of scope for the initial design.

License: MIT
"""
