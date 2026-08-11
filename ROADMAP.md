# Roadmap

ReleaseGuard expands deterministic release evidence without turning an external model or hosted service into the root of trust.

## v0.1 — deterministic release delta gate

- [x] Git diff inspection.
- [x] Protected release-control paths.
- [x] Binary and executable-bit detection.
- [x] npm lifecycle and dependency-source detection.
- [x] JSON evidence report and composite Action.

## v0.2 — review authorization

- [x] GitHub pull-request and review evidence.
- [x] Independent-review quorum and reviewer trust filtering.
- [x] Commit-range binding.
- [x] SARIF and versioned repository evidence schema.
- [x] Pinned project Actions and Dependabot.

## v0.3 — npm registry identity and provenance

- [x] npm trusted-publishing marker policy.
- [x] Official npm cryptographic attestation verification.
- [x] Repository, workflow, commit, ref, builder, and subject identity policy.
- [x] Missing, malformed, invalid, unavailable, and mismatched evidence states.
- [x] npm JSON schema, SARIF, composite Action, and fixture suite.

## v0.4 — ecosystem release surfaces and maintainer operations

- [x] PEP 621 and Poetry dependency-delta rules.
- [x] Python build-backend and dynamic-dependency rules.
- [x] Cargo Git/path/custom-registry dependency rules.
- [x] Cargo patch/replace and build-script rules.
- [x] Fail-closed manifest parsing.
- [x] Release governance and compatibility policy.
- [x] Automated release-readiness validation.
- [x] Tag-driven GitHub Release artifact workflow.
- [x] Consolidated project, funding, maintenance, and demo documentation.

## v0.5 — adoption and additional provenance

- [ ] PyPI trusted-publisher and PEP 740 attestation verification.
- [ ] Baseline mode for mature repositories.
- [ ] Time-bounded, reason-bearing policy exceptions.
- [ ] Native signed ReleaseGuard evidence envelope and verification command.
- [ ] Monorepo package-boundary policy.
- [ ] Dogfood ReleaseGuard in additional public repositories.
- [ ] Convert external compatibility reports into regression fixtures.

## v1.0 criteria

- Stable CLI, policy, finding, report, and fingerprint compatibility commitments.
- At least two ecosystems with end-to-end provenance verification.
- Reproducible release evidence suitable for retention with published releases.
- Documented baseline, exception, false-positive, and deprecation policies.
- Real-world adoption evidence without fabricated usage metrics.
