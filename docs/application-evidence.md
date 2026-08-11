# Maintainer and application evidence

This page records verifiable project evidence without substituting activity for adoption.

## Maintenance history

- [PR #1](https://github.com/jerry0327/ReleaseGuard/pull/1) established the first deterministic scanner, Action, tests, threat model, and OSS project structure.
- [PR #5](https://github.com/jerry0327/ReleaseGuard/pull/5) added independent-review evidence, commit binding, SARIF, schema versioning, and supply-chain hardening.
- [PR #8](https://github.com/jerry0327/ReleaseGuard/pull/8) added npm trusted-publishing and provenance verification with extensive isolation and compatibility tests.
- [PR #6](https://github.com/jerry0327/ReleaseGuard/pull/6) demonstrates reviewed Dependabot maintenance with CI and project-policy checks.
- Issues [#2](https://github.com/jerry0327/ReleaseGuard/issues/2), [#3](https://github.com/jerry0327/ReleaseGuard/issues/3), and [#4](https://github.com/jerry0327/ReleaseGuard/issues/4) were used to define and track substantive roadmap work.

## Ongoing maintainer responsibilities

The primary maintainer is responsible for:

- issue triage and reproduction quality;
- pull-request review and merge decisions;
- stable finding and schema semantics;
- upstream npm/GitHub/SLSA compatibility;
- pinned Action maintenance;
- vulnerability intake and coordinated fixes;
- release readiness, changelog, artifacts, and checksums; and
- documentation and contributor guidance.

## Current evidence of quality

- public MIT-licensed repository;
- multi-version CI;
- deterministic unit and integration fixtures;
- explicit threat model and non-goals;
- private vulnerability-reporting guidance;
- CODEOWNERS, Dependabot, contribution, governance, support, and release policies;
- versioned JSON schemas and SARIF fingerprints;
- automated release-readiness and artifact workflow.

## Adoption statement

ReleaseGuard is early alpha. The project does not currently claim meaningful stars, package downloads, production deployments, or broad ecosystem adoption. Applications should emphasize the software-supply-chain problem, the implemented technical work, and the concrete maintainer workload that support would accelerate.
