# Changelog

All notable changes to this project are documented in this file.

The format is based on Keep a Changelog and this project uses Semantic Versioning.

## [Unreleased]

### Added
- Placeholder for upcoming changes.

## [0.1.0] - 2026-03-07

### Added
- Production-ready live introspection path with object discovery, event sorting/limits, and provenance metadata.
- Provider abstraction for live data fetching (`LiveDataProvider`) with default kubectl-backed provider.
- Retry/backoff controls for transient live fetch failures.
- CLI hardening for live mode argument validation and structured fatal output for machine-readable formats.
- Real-cluster integration suite expansion with archetype-oriented tests (PVC pending, scheduling, crashloop, image pull).
- Installable kubectl plugin entrypoint via packaging scripts (`kubectl-explain-failure`).
- CI matrix workflow with gated live integration job.

### Changed
- Unified plugin wrapper through package module (`kubectl_explain_failure.plugin`).
- Corrected tox dependency path to use repository-level `requirements.txt`.

### Notes
- Live integration tests remain env-gated and are skipped by default unless explicitly enabled.
