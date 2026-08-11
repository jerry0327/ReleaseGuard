# ReleaseGuard project brief

## One sentence

ReleaseGuard is a dependency-free, deterministic security gate that inspects release-critical source changes, validates independent GitHub review evidence, and verifies selected npm provenance claims against the expected repository, workflow, and commit.

## Problem

Open-source maintainers are expected to review large changes while also protecting workflows, package manifests, publication credentials, and downstream users. A small mutation—such as a lifecycle hook, source override, build script, or alternate publish workflow—can have disproportionate supply-chain impact.

Most repositories have separate tools for linting, dependency updates, review rules, and provenance. ReleaseGuard creates one narrow policy record for the release boundary without making a hosted service or language model mandatory.

## Current capabilities

ReleaseGuard `0.4.0` provides:

- stable rules `RG001`–`RG034`;
- Git, npm, PEP 621, Poetry, and Cargo release-delta analysis;
- independent GitHub review quorum and exact commit binding;
- npm CLI-backed cryptographic attestation verification and SLSA identity checks;
- JSON evidence schemas and SARIF 2.1.0;
- two composite GitHub Actions;
- Python 3.11–3.13 CI;
- no third-party Python runtime dependency;
- pinned third-party Actions and documented release governance.

## Intended users

- maintainers of public libraries and developer tools;
- projects adopting npm trusted publishing;
- security-conscious repositories with protected release workflows;
- teams that need machine-readable release evidence without depending on a hosted ReleaseGuard service.

## Design choices

- Deterministic enforcement remains available offline for repository scans.
- Cryptographic verification is delegated to maintained ecosystem tooling rather than reimplemented partially.
- Evidence is bound to exact commits and package versions.
- Reports retain normalized claims, not secrets or large raw evidence bundles.
- Every finding includes a stable ID, severity, detail, path when applicable, and remediation.

## Current maturity

ReleaseGuard is an early-alpha project with one primary maintainer. The repository demonstrates active issue, pull-request, CI, security, and release-process work, but it does not claim external adoption, download volume, or ecosystem criticality that has not yet been established.

The next maturity step is dogfooding in additional public repositories and converting real compatibility findings into regression tests.

## Non-goals

ReleaseGuard does not replace GitHub, package registries, Sigstore, branch protection, protected environments, reproducible builds, source-code review, or maintainer judgment. It does not treat an LLM as a security decision-maker.
