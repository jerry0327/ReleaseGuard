# ReleaseGuard

[![CI](https://github.com/jerry0327/ReleaseGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/jerry0327/ReleaseGuard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Deterministic security gates for source changes, release authorization, and published package provenance.**

ReleaseGuard helps maintainers detect high-leverage software supply-chain changes before release and verify selected evidence after publication. It is designed for GitHub-based open-source projects that want explicit, reviewable policy rather than an opaque model-generated risk score.

> **Status:** early alpha (`0.4.0`). The core enforcement path is usable, tested on Python 3.11–3.13, and dependency-free at Python runtime. Production users should pin ReleaseGuard and every third-party Action to reviewed commit SHAs.

ReleaseGuard does **not** use an LLM as the PASS/BLOCK authority.

## What it protects

ReleaseGuard evaluates three distinct trust boundaries:

1. **Repository delta** — install-time execution, dependency redirection, release-control changes, binaries, executable bits, Python/Cargo build surfaces, and unusually large release changes.
2. **Review authorization** — whether high-risk changes have fresh, independent, trusted approvals bound to the exact pull-request commit.
3. **Published npm artifact** — whether npm cryptographically verified the package's attestations and whether signed provenance matches the expected GitHub repository, workflow, commit, ref, and builder.

The current rule catalogue contains stable IDs `RG001`–`RG034`.

| Rule group | Coverage |
|---|---|
| `RG001`–`RG011` | Generic Git and npm manifest release-delta controls |
| `RG012`–`RG014` | Independent GitHub review evidence and commit binding |
| `RG015`–`RG025` | npm trusted publishing and verified provenance identity |
| `RG026`–`RG029` | PEP 621 / Poetry dependencies and Python build-system changes |
| `RG030`–`RG034` | Cargo Git/path dependencies, source overrides, build scripts, and fail-closed TOML parsing |

See [Rules and rationale](docs/rules.md) for exact semantics, severity, remediation, and expected false positives.

## Pull-request gate

```yaml
name: release-guard

on:
  pull_request:

permissions:
  contents: read
  pull-requests: read

jobs:
  releaseguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0

      # Alpha usage. Pin ReleaseGuard to a reviewed commit SHA in production.
      - uses: jerry0327/ReleaseGuard@main
        with:
          config: releaseguard.toml
          github-token: ${{ github.token }}

      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7
        if: always()
        with:
          name: releaseguard-evidence
          path: |
            releaseguard-report.json
            releaseguard.sarif
```

Independent review is opt-in:

```toml
[releaseguard.review]
minimum_independent_approvals = 1
required_on = "high"
allow_stale_approvals = false
exclude_bots = true
fail_closed = true
allowed_author_associations = ["OWNER", "MEMBER", "COLLABORATOR"]
trusted_reviewers = []
```

Read [Independent review evidence](docs/review-evidence.md) before enabling a blocking quorum.

## CLI

ReleaseGuard requires Python 3.11+ and has no third-party Python runtime dependency.

```bash
python -m pip install .
releaseguard scan --base origin/main --head HEAD
```

Exit codes:

- `0`: policy passed;
- `2`: policy completed and blocked the release;
- `3`: ReleaseGuard could not complete the requested command.

A reproducible malicious-release walkthrough is in [Demo](docs/demo.md).

## npm post-publish gate

Run the dedicated Action after `npm publish` and before deployment or announcement:

```yaml
- uses: jerry0327/ReleaseGuard/actions/verify-npm@main
  with:
    package: ${{ steps.package.outputs.name }}
    version: ${{ steps.package.outputs.version }}
    repository: ${{ github.repository }}
    workflow: .github/workflows/publish.yml
    commit: ${{ github.sha }}
    ref: ${{ github.ref }}
```

The verifier uses a pinned npm CLI in an isolated environment, disables package scripts and bin links, removes inherited credentials and arbitrary Node options, and accepts source claims only from the target package records npm returned as cryptographically verified.

See [npm provenance verification](docs/npm-provenance.md).

## Evidence formats

Repository scans produce:

- `releaseguard-report.json` — schema version 2;
- `releaseguard.sarif` — SARIF 2.1.0;
- [`schemas/releaseguard-report.schema.json`](schemas/releaseguard-report.schema.json).

npm verification produces:

- `releaseguard-npm-report.json` — schema version 1;
- `releaseguard-npm.sarif` — SARIF 2.1.0 with package PURL locations;
- [`schemas/npm-provenance-report.schema.json`](schemas/npm-provenance-report.schema.json).

Raw review discussion, registry credentials, package contents, DSSE envelopes, signing certificates, and transparency-log records are deliberately excluded from durable reports.

## Security boundary

ReleaseGuard is a guardrail, not the repository host, package registry, identity provider, cryptographic transparency service, or CI operating system. It cannot prevent a platform compromise, an administrator disabling every required control, collusion by every trusted reviewer, publication to an unmonitored package name, or malicious source code that violates no configured invariant.

For npm, cryptographic verification is delegated to the official npm CLI. ReleaseGuard applies deterministic identity policy only after npm identifies the target evidence as verified.

Read the complete [Threat model](docs/threat-model.md) and [Security policy](SECURITY.md).

## Project maturity and governance

ReleaseGuard is currently maintained by one primary maintainer. It does not claim stars, downloads, deployments, contributors, or ecosystem adoption that cannot be verified.

The repository includes:

- multi-version CI and integration tests;
- pinned third-party Actions;
- versioned JSON schemas and SARIF fingerprints;
- CODEOWNERS and Dependabot;
- documented governance, support, contribution, security, and release processes;
- an automated release-readiness checker; and
- a tag-driven GitHub Release workflow that builds a wheel, source archive, and checksums.

Start with:

- [Project brief](docs/project-brief.md)
- [Architecture](docs/architecture.md)
- [Adoption guide](docs/adoption-guide.md)
- [Governance](GOVERNANCE.md)
- [Maintainers](MAINTAINERS.md)
- [Support](SUPPORT.md)
- [Releasing](RELEASING.md)
- [Funding and API-credit plan](docs/funding-plan.md)

## Development

```bash
make check
make test
make build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for rule-design, security-review, compatibility, and testing expectations.

## Roadmap

The next work is intentionally narrower than the initial build-out:

- PyPI trusted publishing and PEP 740 attestation verification;
- baseline and time-bounded exception policies for mature repositories;
- native signing and verification of ReleaseGuard evidence envelopes;
- monorepo package-boundary support; and
- real-world dogfooding and externally reported compatibility cases.

See [ROADMAP.md](ROADMAP.md).

## Citation and license

Citation metadata is available in [CITATION.cff](CITATION.cff). ReleaseGuard is licensed under the [MIT License](LICENSE).
