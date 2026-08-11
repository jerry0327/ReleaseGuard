# Changelog

All notable changes to ReleaseGuard are documented here.

## [Unreleased]

### Planned

- PyPI trusted-publisher and PEP 740 attestation verification.
- Baseline and time-bounded exception policies.
- Native signed ReleaseGuard evidence envelopes.
- Monorepo package-boundary support and external dogfooding.

## [0.4.0] - 2026-08-12

### Added

- PEP 621 and Poetry dependency-delta analysis.
- Critical detection for Python direct URL, VCS, and local-path dependencies.
- Python build-backend and build-requirement change detection.
- Detection when dependency fields become dynamically supplied.
- Cargo dependency analysis across runtime, development, build, workspace, and target-specific sections.
- Critical Cargo Git/path dependency, custom registry, patch, and replacement-source detection.
- Cargo `build.rs`, `package.build`, and `package.links` scrutiny.
- Fail-closed TOML manifest parsing with `RG034`.
- Stable ecosystem rule IDs `RG026` through `RG034` and fixture-based tests.
- `GOVERNANCE.md`, `MAINTAINERS.md`, `SUPPORT.md`, and `RELEASING.md`.
- Release-readiness checker, Makefile, and release-consistency tests.
- Tag-driven GitHub Release workflow producing a wheel, source archive, and SHA-256 checksums.
- Project brief, maintainer evidence, funding/API-credit plan, and reproducible demo documentation.

### Changed

- Package version advanced from `0.3.0` to `0.4.0`.
- CI now checks release consistency, builds and installs the wheel, and uses pinned `actions/setup-python` v7.
- Dependabot configuration no longer references repository labels that do not exist.
- README was consolidated around the three actual trust boundaries and verifiable project maturity.

### Security

- Python and Cargo manifests no longer silently bypass ecosystem analysis when TOML parsing fails.
- Cargo source overrides and build-time execution surfaces receive explicit findings.
- Release automation rejects version/tag drift and unpinned external Actions in executable workflows.

## [0.3.0] - 2026-08-12

### Added

- `releaseguard verify-npm` for exact, post-publish npm package verification.
- `actions/verify-npm` composite Action with pinned Node.js `24.18.1` setup and npm `11.19.0`.
- Official npm CLI delegation for Sigstore signature, certificate, transparency-log, registry-signature, and package-subject verification.
- SLSA provenance v1 and v0.2 claim extraction after cryptographic verification.
- Expected repository, workflow, commit, ref, builder, and trusted-publisher policy.
- npm provenance findings `RG015` through `RG025`.
- Explicit `missing`, `invalid`, `unavailable`, and `verified` evidence states.
- npm provenance JSON schema version 1 and SARIF 2.1.0 output.

### Security

- Exact package versions are required; npm tags and ranges are rejected.
- Verification uses an isolated npm project with lifecycle scripts and inherited credentials disabled.
- Raw Sigstore bundles, credentials, package contents, and unbounded command output are not persisted.

## [0.2.0] - 2026-08-12

### Added

- Optional independent-review quorum triggered by finding severity.
- Fresh-commit, non-author, non-bot, trusted-reviewer filtering.
- Commit-range binding and review findings `RG012`–`RG014`.
- SARIF 2.1.0 output and JSON evidence schema version 2.
- CODEOWNERS, Dependabot, adoption documentation, and Python 3.13 CI coverage.

## [0.1.0] - 2026-08-12

### Added

- Dependency-free Python release-diff scanner.
- Composite GitHub Action integration.
- Deterministic policy rules `RG001` through `RG011`.
- JSON evidence report, job summary, TOML policy, tests, CI, threat model, and OSS governance files.
