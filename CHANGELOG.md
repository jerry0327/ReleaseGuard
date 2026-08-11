# Changelog

All notable changes to ReleaseGuard are documented here.

## [Unreleased]

### Planned

- npm trusted-publishing and provenance verification.
- Signed ReleaseGuard evidence envelopes.
- First-class PyPI and Cargo dependency rules.

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
