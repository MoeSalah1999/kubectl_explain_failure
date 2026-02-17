"""
# kubectl-explain-failure

This project explores a gap in Kubernetes diagnostics: the system exposes raw signals but not causal explanations. The tool reads Pod and Event data and applies explicit heuristics to explain why a workload failed.

A small, diagnostic tool that explains **why a Kubernetes Pod is failing** by
correlating Pod status and Events into a human-readable explanation.

## Problem
Kubernetes exposes raw signals (Pod status, Events), but operators still have to manually
interpret *why* something failed. This tool demonstrates how causal explanations can be
constructed from existing Kubernetes data without modifying the cluster.

For example:
- A Pod is `Pending`, but the underlying scheduling constraint is not obvious
- A container is restarting, but the root cause is buried in Events or status fields
- Volume or image failures require manual correlation across multiple objects

This tool explores how **causal explanations** can be constructed from existing Kubernetes data alone.

## What this tool does
- Reads Kubernetes objects from JSON files (Pod, Events; optional PVC / Node)
  - Required: Pod, Events
  - Optional: PVC, Node, or folder of multiple PVCs
- Applies explicit, rule-based heuristics for common failure patterns
- Produces a structured explanation containing:
  - Root cause
  - Evidence
  - Likely causes
  - Suggested next checks
  - Confidence score

The output is deterministic and fully testable.

## What this tool does NOT do
- No live cluster access
- No Kubernetes API client
- No controllers, CRDs, or admission hooks
- No automatic remediation
- No machine learning or prediction

This is a **diagnostic explainer**, not a fixer.

## Installation (Development Mode)

To install the package locally in development mode, allowing editable imports:

- git clone https://github.com/MoeSalah1999/kubectl_explain_failure
- cd kubectl_explain_failure
- python -m pip install -e .

This ensures you can import the package as:

from kubectl_explain_failure.engine import explain_failure

and run tests or scripts directly.

## Usage
Basic usage:
python -m kubectl_explain_failure \
  --pod /kubectl_explain_failure/tests/fixtures/pod.json \
  --events /kubectl_explain_failure/tests/fixtures/events.json


With optional PVC or Node context:
python -m kubectl_explain_failure \
  --pod /kubectl_explain_failure/tests/fixtures/pending_pod.json \
  --events /kubectl_explain_failure/tests/fixtures/empty_events.json \
  --pvc /kubectl_explain_failure/tests/fixtures/pvc_pending.json \
  --node /kubectl_explain_failure/tests/fixtures/node_disk_pressure.json


## Testing

This project uses pytest and tox. Tests are **not included in the installed package** and must be run from the source tree.
To run tests in the development environment:

- tox
- tox -e format   # code formatting
- tox -e lint     # static linting
- tox -e typing   # mypy type checks
- tox -e test     # pytest suite, including golden tests

Tox automatically installs required dependencies, including:

pytest
mypy
PyYAML

This ensures tests run in a clean environment and type checks are enforced.

## Supported failure patterns: (all rules support suppression/resolution semantics):

- AdmissionWebhookDenied
- AffinityUnsatisfiable
- CNIPluginFailure
- CrashLoopBackoff (BackOff events)
- ConfigMapNotFound
- ContainerCreateConfigError
- DeploymentProgressDeadlineExceeded
- DNSResolutionFailure
- EvictedRule
- FailedScheduling
- FailedMount (volume mount failures)
- HostPortConflict 
- ImagePullBackOff 
- ImagePullError
- ImagePullSecretMissing
- InsufficientResources
- InvalidEntrypoint
- LimitRangeViolation
- NodeMemoryPressure
- NodePIDPressure
- NodeDiskPressure 
- NodeSelectorMismatch
- OOMKilled containers
- PreemptedByHigherPriority
- PrivilegedNotAllowed
- PVReleasedOrFailed
- PVCMountFailed 
- PVCNotBound 
- PVCZoneMismatch
- RBACForbidden
- ReadinessProbeFailure
- ResourceQuotaExceeded
- ReplicaSetCreateFailure
- ReplicaSetUnavailable
- SecurityContextViolation
- StatefulSetUpdateBlocked
- StartupProbeFailure
- StorageClassProvisionerMissing
- TopologySpreadUnsatisfiable
- UnschedulableTaint  
---------------------------------------------------------------------------------------------------------------------------------------
- CrashLoopAfterConfigChange (Compound)
- CrashloopWithConfigOrSecret (Compound)                                                 
- CrashloopLivenessProbeRule (Compound)
- CrashloopOOMKilledRule (Compound)
- DynamicProvisioningTimeout (Compound)
- ImagePullSecretMissingCompound (Compound)
- ImageUpdatedThenCrashLoop (Compound)
- InitContainerFailureRule (Compound)
- NetworkPolicyBlocked (Compound)
- NodeNotReadyEvictedRule (Compound)
- OwnerBlockedPod (Compound)
- PendingUnschedulableRule (Compound)
- PriorityPreemptionChain (Compound)
- PVCBoundThenNodePressureRule (Compound)
- PVCBoundNodeDiskPressureMountRule (Compound)
- PVCMountFailureRule (Compound)
- PVCPendingThenCrashloopRule (Compound)
- PVCPendingTooLongRule (Compound)
- PVCRecoveredButAppStillFailing (Compound)
- PVCThenCrashloopRule(Compound)
- PVCThenImagePullFailRule (Compound)
- RapidRestartEscalationRule (Compound)
- RepeatedProbeFailureEscalation (Compound)
- SchedulingFlapping (Compound)
- ServiceAccountMissingRule (Compound)
- ServiceAccountRBAC (Compound)

- Rules are evaluated in priority order.
- High-priority rules can suppress lower-priority rules, preventing misleading explanations.
- First matching, unsuppressed rule produces the explanation.
- Golden tests assert that suppression works correctly.


## Design notes
- Rule-based, not implicit
Each diagnostic is an explicit rule that can be reviewed, tested, and extended.

- Read-only by design
All inputs are files; no cluster mutation or API access is required.

- Deterministic output
The same inputs always produce the same explanation.

- Reviewable architecture
Heuristics are isolated from parsing and output logic.

## Why this exists (despite kubectl describe)

kubectl describe exposes raw data.
This tool answers a different question:

“Given these signals, what is the most likely reason this Pod is failing?”

It complements existing tooling rather than replacing it.

## Architecture overview

- FailureRule defines a diagnostic contract:
  - matches(...)
  - explain(...)
- Rules are evaluated in order
- The first matching rule produces the explanation
- If no rule matches, a safe default explanation is returned

This structure allows incremental expansion without increasing complexity.

## Future work

- Additional failure heuristics
- Structured output for automation
- Optional kubectl plugin wrapper

Live cluster access is intentionally out of scope for the initial design.

License: MIT
"""
