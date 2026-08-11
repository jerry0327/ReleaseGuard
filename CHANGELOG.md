# Changelog

All notable changes to ReleaseGuard are documented here.

## [Unreleased]

### Planned

- First-class PyPI and Cargo dependency/provenance rules.
- Baseline and time-bounded exception policies.
- Native signed ReleaseGuard evidence envelopes.

## [0.3.0] - 2026-08-12

### Added

- `releaseguard verify-npm` for exact, post-publish npm package verification.
- `actions/verify-npm` composite Action with pinned Node.js `24.18.1` setup and npm `11.19.0`.
- Official npm CLI delegation for Sigstore signature, certificate, transparency-log, registry-signature, and package-subject verification.
- SLSA provenance v1 and v0.2 claim extraction after cryptographic verification.
- Compatible parsing for npm 11 object and npm 12 single-item array output from exact `npm view --json` queries.
- Expected repository, workflow, commit, ref, builder, and trusted-publisher policy.
- npm provenance findings `RG015` through `RG025`.
- Explicit `missing`, `invalid`, `unavailable`, and `verified` evidence states.
- Registry propagation retries for post-publish workflows.
- npm provenance JSON schema version 1 and SARIF 2.1.0 output using package PURL locations.
- Post-publish workflow examples, including optional first-party attestation of the ReleaseGuard report.
- Unit, parser, policy, reporting, CLI, and subprocess-boundary tests.

### Security

- Exact package versions are required; npm tags and ranges are rejected.
- Verification uses an isolated temporary npm project with lifecycle scripts, optional dependencies, and bin links disabled.
- Verifier subprocesses receive an allowlisted environment; inherited GitHub, npm, Node, cloud, and other credentials plus arbitrary Node options are excluded.
- Registry URLs require HTTPS, except localhost test endpoints, and cannot contain embedded credentials.
- npm output, DSSE payload, attestation count, subprocess duration, retry count, and input identities are bounded and validated.
- Raw Sigstore bundles, certificates, transparency-log entries, auth tokens, and package contents are not persisted in reports.

### Changed

- Package version advanced from `0.2.0` to `0.3.0`.
- The README and threat model now separate repository-delta, review-authorization, and registry-artifact trust boundaries.
- Native signed ReleaseGuard envelopes remain roadmap work; first-party GitHub artifact attestation integration is documented instead of claiming an incomplete signing implementation.

## [0.2.0] - 2026-08-12

### Added

- Optional independent-review quorum triggered by configurable finding severity.
- GitHub pull-request and review evidence retrieval using a dependency-free REST client.
- Fresh-commit, non-author, non-bot, trusted-reviewer filtering.
- Default trust restriction to `OWNER`, `MEMBER`, and `COLLABORATOR` author associations.
- Explicit `trusted_reviewers` support for named external auditors.
- Base/head commit-range binding with critical `RG014` on mismatch.
- Review findings `RG012`–`RG014` and structured review evidence in report schema v2.
- SARIF 2.1.0 output with stable fingerprints.
- JSON Schema for ReleaseGuard report schema v2.
- Review-evidence, SARIF, rule, adoption, and report-schema documentation.
- Python 3.13 CI coverage and an end-to-end malicious release fixture.
- CODEOWNERS and Dependabot configuration.

### Security

- Pinned ReleaseGuard's own third-party GitHub Actions to full reviewed commit SHAs.
- Sanitized GitHub API errors, HTTPS origin validation, response-size limits, and pagination limits.
- Tokens are accepted through environment/action input only and are not written to reports.

### Changed

- Package version advanced from `0.1.0` to `0.2.0`.
- JSON evidence schema advanced from version 1 to version 2.
- Git refs are resolved to full commit SHAs before scanning and evidence binding.

## [0.1.0] - 2026-08-12

### Added

- Dependency-free Python release-diff scanner.
- Composite GitHub Action integration.
- Deterministic policy rules `RG001` through `RG011`.
- JSON evidence report and GitHub Actions job summary.
- TOML policy configuration.
- Unit tests, CI workflow, threat model, policy reference, security policy, and contribution guide.
