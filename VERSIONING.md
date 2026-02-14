# Versioning Policy

This repository uses SemVer with a pre-1.0 production policy.

## Current stage
- Current baseline: `0.1.0`
- This service is security-sensitive; release changes are expected to be conservative and audit-friendly until `1.0.0`.

## Pre-1.0 bump rules (`0.y.z`)
- `PATCH` (`0.y.z+1`):
  - security fixes
  - bug fixes
  - policy tightening that is backward-compatible for valid clients
  - docs/CI changes
- `MINOR` (`0.y+1.0`):
  - any change to request/response schema
  - auth/signing contract changes for clients
  - env var contract changes
  - behavior changes that may require client updates

## `1.0.0` readiness criteria
- Stable API and auth contract documented in `docs/api-spec.yaml`.
- Security gates enforced in CI and exercised in release flow.
- Key hardening controls validated through regression tests.

## Release process
1. Update `CHANGELOG.md` under `Unreleased`.
2. Select next version using rules above.
3. Create release section with date.
4. Tag release commit as `v0.y.z` (annotated).
5. Publish release notes from changelog.

