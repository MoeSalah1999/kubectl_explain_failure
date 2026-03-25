
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

> "What is the most likely reason this Pod is failing?"

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

> "requires = {
    "objects": ["pvc", "pv"],
    "optional": ["storageclass"]
}"

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
      * evidence_quality
      * data_completeness
      * conflict_penalty


This makes confidence:

- Deterministic
- Explainable
- Predictable under partial input
- Stable under rule reordering

Confidence is always bounded to [0,1].


# Supported failure patterns

This list mirrors the codebase taxonomy under `rules/base`, `rules/compound`,
`rules/temporal`, and `rules/resolution`.

## Base Rules

### Admission

- AdmissionWebhookDenied
- AdmissionWebhookServiceUnavailable
- AdmissionWebhookCABundleMismatch
- AdmissionWebhookDNSFailure
- EtcdObjectSizeLimitExceeded
- ImagePolicyWebhookRejected
- LimitRangeViolation
- MutatingWebhookPatchConflict
- MutatingWebhookTimeout
- OPAConstraintViolation
- PrivilegedNotAllowed
- PSARestrictedViolation
- RBACForbidden
- ResourceQuotaExceeded
- SecurityContextViolation
- ServiceAccountMissing
- ServiceAccountRBAC
- TokenProjectionFailure
- ValidatingWebhookTimeout
- WebhookCertificateExpired

### Container

- ContainerCreateConfigError
- ContainerRuntimePermissionDenied
- ContainerRuntimeStartFailure
- CrashLoopBackOff
- ImageArchitectureMismatch
- ImagePullBackOff
- ImagePullError
- ImagePullSecretMissing
- InitContainerFailure
- InvalidEntrypoint
- OOMKilled
- PreStopHookFailure
- ReadOnlyRootFilesystemWriteAttempt
- TerminationGracePeriodExceeded

### Controllers

- CRDConversionWebhookFailure
- DaemonSetNodeSelectorMismatch
- DeploymentProgressDeadlineExceeded
- DeploymentReplicaMismatch
- HeadlessServiceMissingForStatefulSet
- ImmutableFieldUpdateRejected
- PodDisruptionBudgetBlocking
- ReplicaSetCreateFailure
- ReplicaSetUnavailable
- StatefulSetUpdateBlocked

### Networking

- CNIPluginFailure
- DNSResolutionFailure
- ServiceEndpointsEmpty
- ServiceNotFound

### Node

- ContainerRuntimeUnavailable
- ContainerRuntimeVersionMismatch
- EphemeralStorageExceeded
- Evicted
- KubeletCertificateExpired
- KubeletNotResponding
- NodeDiskPressure
- NodeClockSkewDetected
- NodeMemoryPressure
- NodeNotReady
- NodePIDPressure

### Probes

- ReadinessProbeFailure
- StartupProbeFailure

### Scheduling

- AffinityUnsatisfiable
- ExtendedResourceUnavailable
- FailedScheduling
- HostPortConflict
- InsufficientResources
- NodeAffinityRequiredMismatch
- NodeFragmentationPreventsPreemption
- NodeSelectorMismatch
- NodeUnschedulableCordoned
- PodAntiAffinityDeadlock
- PodOverheadExceededNodeCapacity
- PodTopologySpreadLabelMismatch
- PodTopologySpreadSkewTooHigh
- PreemptedByHigherPriority
- PreemptionIneffectiveDueToAffinity
- PreemptionIneffectiveDueToPDB
- PreemptionIneffectiveDueToTopologySpread
- RegistryRateLimited
- RuntimeClassNotFound
- SchedulerExtenderFailure
- TopologySpreadUnsatisfiable
- TopologyKeyMissing
- UnschedulableTaint
- VolumeNodeAffinityConflict

### Storage

- AccessModeMismatch
- CSIPluginNotRegistered
- ConfigMapNotFound
- FailedMount
- FilesystemResizePending
- PVCMountFailed
- PVCNotBound
- PVReleasedOrFailed
- ReadWriteOnceMultiNodeConflict
- StorageClassProvisionerMissing

## Compound Rules

### Admission

- PolicyEngineUnavailable

### Container

- CrashLoopAfterConfigChange
- CrashLoopLivenessProbe
- CrashLoopOOMKilled
- ImagePullSecretMissingCompound
- ImageTagMutableDrift
- ImageUpdatedThenCrashLoop
- RapidRestartEscalation

### Controllers

- HPAUnableToScale
- OwnerBlockedPod
- RollingUpdateStuckMidway
- WebhookFailureBlocksDeployment

### Cross-Domain

- ClusterResourceStarvationCascade
- ConfigChangedButPodNotRestarted

### Multi-Container

- InitContainerBlocksMain
- MultiContainerPartialFailure
- SidecarInjectionFailure

### Networking

- HostNetworkPortConflict
- NetworkPolicyBlocked

### Node

  - ConflictingNodeConditions
  - CrashLoopAfterNodeDrain
  - KubeletRestartLoop
  - NodeDiskPressureThenEviction
  - NodeNetworkUnavailableCascade
  - NodeNotReadyEvicted
  - NodePressureEvictionCascade
  - PVCBoundNodeDiskPressureMount
  - PVCBoundThenNodePressure

### Probes

- RepeatedProbeFailureEscalation

### Scheduling

- CrossZoneSchedulingConflict
- PendingUnschedulable
- PriorityPreemptionChain
- SchedulerPreemptionLoop
- SchedulingFlapping
- UnschedulableDueToPDB

### Storage

- DynamicProvisioningTimeout
- PVCBoundThenCrashLoop
- PVCMountFailure
- PVCPendingThenCrashLoop
- PVCPendingTooLong
- PVCRecoveredButAppStillFailing
- PVCThenCrashLoop
- PVCThenImagePullFail
- VolumeSchedulingDeadlock

## Temporal Rules

### Admission

- IntermittentAdmissionWebhookFailure

### Auth

- ExpiredServiceAccountToken

### Container

- InitContainerImagePullThenMainCrash
- ProbeTooAggressiveCausingRestarts

### Networking

- CNIIPExhaustion
- IntermittentNetworkFlapping

### Scheduling

- RepeatedSchedulingBackoff
- SchedulingConstraintOscillation
- SchedulingTimeoutExceeded

### Storage

- VolumeAttachmentTimeout

## Resolution Rules

- ConflictingSignalsResolution
- RootCauseAmbiguity



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

## Installation (Packaged)

Install the packaged CLI/plugin entrypoint:

- `python -m pip install kubectl-explain-failure`

This installs the console script:

- `kubectl-explain-failure`

For local packaged testing from source:

- `python -m pip install .`

# Versioning and Changelog

- Versioning uses Semantic Versioning.
- Current release version is `0.1.0`.
- Release history is tracked in `CHANGELOG.md`.

## Release checklist

- Bump `version` in `pyproject.toml`
- Add release notes under a new version in `CHANGELOG.md`
- Tag release in git
- Publish package build

# Usage
## Snapshot mode (file inputs):
python -m kubectl_explain_failure \
  --pod /kubectl_explain_failure/tests/fixtures/pod.json \
  --events /kubectl_explain_failure/tests/fixtures/events.json


## With optional PVC or Node context:
python -m kubectl_explain_failure \
  --pod /kubectl_explain_failure/tests/fixtures/pending_pod.json \
  --events /kubectl_explain_failure/tests/fixtures/empty_events.json \
  --pvc /kubectl_explain_failure/tests/fixtures/pvc_pending.json \
  --node /kubectl_explain_failure/tests/fixtures/node_disk_pressure.json


## Live introspection (production-ready path):
python -m kubectl_explain_failure \
  pod my-pod \
  --live \
  --namespace default \
  --format json

### Live mode flags:
- `--namespace`, `--context`, `--kubeconfig`
- `--timeout`
- `--event-limit`, `--event-chunk-size`
- `--retries`, `--retry-backoff`
- `--trace-id` (correlate structured live-fetch logs across components)

### Kubectl plugin wrapper:
The `kubectl-explain-failure` plugin forwards directly to the live CLI path.

Example:
- `kubectl explain-failure my-pod -n default --format json`

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

# CI and Live Test Gating

GitHub Actions workflow is defined at:

- `.github/workflows/ci.yml`

It provides:

- Matrix quality/test job across OS and Python versions
- Gated live integration job (manual dispatch only)

## Running gated live job

- Trigger workflow with `run_live=true`
- Configure required repository secrets for live-cluster pod targets and kube access

# Testing

### The project uses:

- pytest
- hypothesis (property-based testing)
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
- hypothesis
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
- Live CLI provenance metadata
- Live provider abstraction behavior
- Live provider retry behavior (transient vs non-retryable errors)

## Property-Based Testing & Snapshot Generator

The project includes a reusable Hypothesis snapshot generator for Kubernetes-style inputs:

- file: `kubectl_explain_failure/tests/property/strategies.py`
- primary APIs:
  - `snapshot_strategy()`
  - `crashloop_snapshot_strategy()`
  - `pvc_scheduler_snapshot_strategy()`
  - `malformed_snapshot_strategy()`
  - `crashloop_oom_snapshot_strategy()`
  - `unrelated_noise()`

The generator produces coherent engine inputs (`pod`, `events`, `context`) and supports snapshot cloning/injection for monotonicity and idempotence properties.

### Hypothesis profiles

Property tests are configured through:

- file: `kubectl_explain_failure/tests/property/conftest.py`
- profiles:
  - `fast` (default, local dev)
  - `deep` (higher example count for CI/fuzzing)

Run with default profile:

- `venv\\Scripts\\python.exe -m pytest kubectl_explain_failure/tests/property -q`

Run with deep profile:

- PowerShell: `$env:HYPOTHESIS_PROFILE="deep"`
- then: `venv\\Scripts\\python.exe -m pytest kubectl_explain_failure/tests/property -q`

### Invariants covered by property tests

Property suite validates engine-level invariants such as:

- idempotence / determinism for identical snapshots
- monotonicity under unrelated object noise
- causal-chain structural integrity
- confidence bounds and output contract stability
- suppression/resolution integrity
- category gating and rule dependency/phase/state gating




### Live adapter test coverage

The live path is covered at three levels:

- Regression/unit tests with mocked providers and kubectl responses
- Property tests for live adapter normalization and metadata invariants
- Optional real-cluster integration smoke tests (env-gated):
  - `kubectl_explain_failure/tests/integration/test_live_adapter_integration.py`
  - set `KUBECTL_EXPLAIN_FAILURE_RUN_LIVE_INTEGRATION=1` to enable

# Architecture Overview
### Core modules:

- engine.py - rule evaluation, resolution, confidence composition
- causality.py - CausalChain and Resolution structures
- context.py - context normalization
- timeline.py - normalized timeline abstraction
- relations.py - object dependency graph logic
- loader.py - rule and plugin discovery
- live_adapter.py - live data adapter, provider abstraction, retries, partial-fetch handling
- cli.py - snapshot/live orchestration, provenance, live completeness confidence penalty
- rules/ - rule corpus (Python + YAML)
- tests/ - golden + regression + contract tests
- tests/property/strategies.py - reusable Hypothesis Kubernetes snapshot generator
- tests/property/conftest.py - property-testing profile configuration

### Rule contract (base_rule.py):

>
> class FailureRule:
>
>     name: str
>     category: str
>     priority: int
>     requires: dict
> 
>     def matches(...)
>     def explain(...)


All rules must be deterministic and side-effect free.

# What this tool does NOT do
- No cluster mutation
- No remediation
- No automatic fixes
- No ML-based inference or prediction
- No probabilistic ranking beyond deterministic confidence composition

This is a **diagnostic explainer**, not a fixer.

# Design Principles

- Deterministic over heuristic guessing
- Explicit over implicit
- Structured causality over flat strings
- Object state over event heuristics
- Suppression over ambiguity
- Fully testable behavior

# Future work

- Additional failure heuristics and rule coverage
- Expanded real-cluster integration scenarios for CI/nightly
- Additional provider implementations behind the live adapter interface

License: MIT







