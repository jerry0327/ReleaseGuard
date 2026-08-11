# Roadmap

ReleaseGuard is intentionally starting with deterministic release invariants. The roadmap expands the evidence available to that policy engine without turning an external model or service into the root of trust.

## v0.1 — deterministic release delta gate

- [x] Git diff inspection.
- [x] Protected release-control paths.
- [x] Binary and executable-bit detection.
- [x] npm lifecycle hook detection.
- [x] Non-registry dependency source detection.
- [x] Dependency-addition and version/changelog signals.
- [x] JSON evidence report.
- [x] GitHub composite action.
- [x] CI test workflow.

## v0.2 — release identity and provenance

- [ ] GitHub API evidence for approvals, authorship, and release actor.
- [ ] Configurable independent-review quorum for high-risk findings.
- [ ] npm trusted-publishing / OIDC verification guidance and checks.
- [ ] Verify published provenance/attestations against the expected repository and commit.
- [ ] Signed ReleaseGuard evidence envelope.

## v0.3 — ecosystem coverage

- [ ] PyPI / `pyproject.toml` dependency-delta rules.
- [ ] Cargo dependency and build-script rules.
- [ ] Package-manager-specific lockfile consistency checks.
- [ ] Monorepo package boundary support.

## v0.4 — maintainer ergonomics

- [ ] Baseline mode for adopting ReleaseGuard on mature repositories.
- [ ] Policy packs for library, CLI, GitHub Action, and monorepo release profiles.
- [ ] SARIF output.
- [ ] Optional AI-assisted explanations for ambiguous cross-file findings, with deterministic enforcement retained.

## v1.0 criteria

- Stable policy schema and finding IDs.
- At least two package ecosystems with end-to-end provenance verification.
- Reproducible release evidence suitable for retention alongside published releases.
- Documented false-positive tuning and backwards-compatibility policy.
