# Roadmap

ReleaseGuard starts with deterministic release invariants and expands the evidence available to that policy engine without turning an external model or hosted service into the root of trust.

## v0.1 — deterministic release delta gate

- [x] Git diff inspection.
- [x] Protected release-control paths.
- [x] Binary and executable-bit detection.
- [x] npm lifecycle hook detection.
- [x] Non-registry dependency-source detection.
- [x] Dependency-addition and version/changelog signals.
- [x] JSON evidence report.
- [x] GitHub composite action.
- [x] CI test workflow.

## v0.2 — release review identity

- [x] GitHub pull-request and review evidence.
- [x] Configurable independent-review quorum for high-risk findings.
- [x] Self, bot, stale, untrusted, and changes-requested review handling.
- [x] Commit-range binding between scan and approval evidence.
- [x] Fail-closed / warn behavior for unavailable review evidence.
- [x] SARIF 2.1.0 output and stable fingerprints.
- [x] Versioned JSON evidence schema.
- [x] Self-hosted supply-chain hardening with pinned Actions and Dependabot.

## v0.3 — registry identity and provenance

- [ ] npm trusted-publishing / OIDC verification guidance and checks.
- [ ] Verify published provenance against expected repository, workflow, and commit.
- [ ] Distinguish absent, malformed, invalid, and mismatched provenance.
- [ ] Signed ReleaseGuard evidence envelope.
- [ ] Registry fixture suite and failure-mode documentation.

## v0.4 — ecosystem coverage

- [ ] PyPI / `pyproject.toml` dependency-delta rules.
- [ ] Cargo dependency and build-script rules.
- [ ] Package-manager-specific lockfile consistency checks.
- [ ] Monorepo package-boundary support.

## v0.5 — maintainer ergonomics

- [ ] Baseline mode for mature repositories.
- [ ] Time-bounded, reason-bearing policy exceptions.
- [ ] Policy packs for library, CLI, GitHub Action, and monorepo release profiles.
- [ ] Optional AI-assisted explanations for ambiguous cross-file findings, with deterministic enforcement retained.

## v1.0 criteria

- Stable policy and report schemas.
- At least two package ecosystems with end-to-end provenance verification.
- Reproducible release evidence suitable for retention alongside published releases.
- Documented exception, false-positive, and backwards-compatibility policies.
- Real-world adoption evidence without fabricated usage metrics.
